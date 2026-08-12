package net.hugmesh.adminbff.urlregistry;

import com.datastax.oss.driver.api.core.CqlSession;
import com.datastax.oss.driver.api.core.cql.Row;
import com.datastax.oss.driver.api.core.cql.SimpleStatement;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Repository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;
import net.hugmesh.adminbff.cassandra.CassandraSessionFactory;

import jakarta.annotation.PreDestroy;
import java.net.InetSocketAddress;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

/**
 * Cassandra-backed store for hugmesh_gateway.url_registry — the DB-driven
 * gateway ROUTE-DEFINITION source of truth (NOT route-access; see
 * hugmesh-gateway {@code UrlRegistryService}, which polls this very table and
 * turns it into live routes). Because the gateway reads this table directly,
 * Cassandra is authoritative here — unlike the route-access {@code RouteRule}
 * flow where Postgres is the source and Cassandra is only a best-effort mirror.
 *
 * <p>The {@link CqlSession} is built lazily and reused, with the same
 * contact-point/local-dc/keyspace wiring as {@code CassandraRouteMirror}.
 * {@code path_prefix} is the primary key, so an INSERT is a natural upsert.
 */
@Repository
public class UrlRegistryRepository {

    private final boolean enabled;
    private final String contactPoint;   // host:port
    private final String localDc;
    private final String keyspace;
    private final CassandraSessionFactory sessionFactory;
    private volatile CqlSession session;

    public UrlRegistryRepository(
            @Value("${app.mirror.cassandra.enabled:true}") boolean enabled,
            @Value("${app.mirror.cassandra.contact-point:cassandra.hugmesh-pki.svc.cluster.local:9042}") String contactPoint,
            @Value("${app.mirror.cassandra.local-dc:dc1}") String localDc,
            @Value("${app.mirror.cassandra.keyspace:hugmesh_gateway}") String keyspace,
            CassandraSessionFactory sessionFactory) {
        this.enabled = enabled;
        this.contactPoint = contactPoint;
        this.localDc = localDc;
        this.keyspace = keyspace;
        this.sessionFactory = sessionFactory;
    }

    private CqlSession session() {
        if (!enabled) throw new IllegalStateException("url-registry Cassandra access disabled");
        CqlSession s = session;
        if (s != null) return s;
        synchronized (this) {
            if (session == null) {
                String[] hp = contactPoint.split(":", 2);
                int port = hp.length > 1 ? Integer.parseInt(hp[1].trim()) : 9042;
                // SHIPS DARK: harden() applies auth + TLS only when the
                // app.mirror.cassandra.{auth,ssl}.enabled flags are ON (default OFF);
                // with them off this is a no-op and the builder is unchanged.
                session = sessionFactory.harden(CqlSession.builder()
                        .addContactPoint(new InetSocketAddress(hp[0].trim(), port))
                        .withLocalDatacenter(localDc)
                        .withKeyspace(keyspace))
                        .build();
            }
            return session;
        }
    }

    /**
     * Reactive list — the blocking Cassandra driver call is wrapped on a
     * bounded-elastic scheduler so it never blocks the WebFlux event loop.
     */
    public Flux<UrlRoute> list() {
        return Mono.fromCallable(this::listBlocking)
                .subscribeOn(Schedulers.boundedElastic())
                .flatMapMany(Flux::fromIterable);
    }

    private List<UrlRoute> listBlocking() {
        List<UrlRoute> out = new ArrayList<>();
        for (Row row : session().execute(SimpleStatement.builder(
                "SELECT path_prefix, downstream_uri, service_name, required_role, strip_prefix FROM url_registry")
                .build())) {
            // strip_prefix is nullable (rows seeded before gateway migration 008,
            // or routes that don't strip). getObject keeps NULL as null — a raw
            // getInt would coerce NULL to 0; null is the "no strip" sentinel the
            // gateway and DTO use, so preserve it rather than silently making it 0.
            Object sp = row.getObject("strip_prefix");
            Integer stripPrefix = (sp instanceof Number n) ? n.intValue() : null;
            out.add(new UrlRoute(
                    row.getString("path_prefix"),
                    row.getString("downstream_uri"),
                    row.getString("service_name"),
                    row.getString("required_role"),
                    stripPrefix));
        }
        out.sort((a, b) -> {
            String pa = a.pathPrefix() == null ? "" : a.pathPrefix();
            String pb = b.pathPrefix() == null ? "" : b.pathPrefix();
            return pa.compareTo(pb);
        });
        return out;
    }

    /** Upsert a route definition (path_prefix is the PK), stamping registered_at. */
    public Mono<UrlRoute> upsert(UrlRoute r) {
        // Execute the blocking Cassandra INSERT on boundedElastic then return the route.
        return Mono.fromCallable(() -> insertRoute(r)).subscribeOn(Schedulers.boundedElastic());
    }

    /** Blocking Cassandra INSERT for a single route row; returns the route for pass-through. */
    private UrlRoute insertRoute(UrlRoute r) {
        session().execute(SimpleStatement.builder(
                "INSERT INTO url_registry "
                + "(path_prefix, downstream_uri, service_name, registered_at, required_role, strip_prefix) "
                + "VALUES (?, ?, ?, ?, ?, ?)")
                .addPositionalValues(r.pathPrefix(), r.downstreamUri(), r.serviceName(),
                        Instant.now(), r.requiredRole() == null ? "" : r.requiredRole(),
                        // null => 0 ("no strip"), matching the gateway's own upsert.
                        r.stripPrefix() == null ? Integer.valueOf(0) : r.stripPrefix())
                .build());
        return r;
    }

    public Mono<Void> delete(String pathPrefix) {
        return Mono.<Void>fromRunnable(() ->
                        session().execute(SimpleStatement.builder(
                                "DELETE FROM url_registry WHERE path_prefix = ?")
                                .addPositionalValue(pathPrefix).build()))
                .subscribeOn(Schedulers.boundedElastic());
    }

    @PreDestroy
    void close() {
        CqlSession s = session;
        if (s != null) {
            try { s.close(); } catch (Exception ignore) { } //NOPMD EmptyCatchBlock - best-effort close
        }
    }
}
