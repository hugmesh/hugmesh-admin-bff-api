package net.hugmesh.adminbff.routeaccess;

import com.datastax.oss.driver.api.core.CqlSession;
import com.datastax.oss.driver.api.core.cql.ResultSet;
import com.datastax.oss.driver.api.core.cql.Row;
import com.datastax.oss.driver.api.core.cql.SimpleStatement;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;
import net.hugmesh.adminbff.cassandra.CassandraSessionFactory;

import jakarta.annotation.PreDestroy;
import java.net.InetSocketAddress;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Supplier;

/**
 * Best-effort Cassandra mirror of the Postgres route-access rules into the
 * keyspace/table the gateways poll (hugmesh_gateway.gateway_route_access —
 * see hugmesh-gateway GatewayRouteAccessService). A Postgres rule carries a
 * Casdoor role + optional casdoor_user; the gateway model is subject-typed, so
 * we map: casdoor_user present → (subject_kind=user, subject_value=user),
 * else → (subject_kind=role, subject_value=role).
 *
 * <p>The CqlSession is built lazily and every operation is wrapped: if Cassandra
 * is unconfigured or unreachable, the mirror logs and no-ops so the
 * authoritative Postgres write is never lost. (The gateways also re-derive from
 * Postgres on their own refresh in a full deployment; the mirror just makes the
 * change visible sooner.)
 */
@Component
public class CassandraRouteMirror implements RouteMirror {

    private static final Logger log = LoggerFactory.getLogger(CassandraRouteMirror.class);

    private final boolean enabled;
    private final String contactPoint;   // host:port
    private final String localDc;
    private final String keyspace;
    private final CassandraSessionFactory sessionFactory;
    private volatile CqlSession session;

    public CassandraRouteMirror(
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
        if (!enabled) return null;
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

    @Override
    public Mono<Void> upsert(RouteRule r) {
        boolean userScoped = r.casdoorUser() != null && !r.casdoorUser().isBlank();
        String subjectKind = userScoped ? "user" : "role";
        String subjectValue = userScoped ? r.casdoorUser() : r.role();
        return run(() -> session().execute(SimpleStatement.builder(
                "INSERT INTO gateway_route_access " +
                "(id, gateway, url_pattern, subject_kind, subject_value, allow, updated_at) " +
                "VALUES (?, ?, ?, ?, ?, ?, toTimestamp(now()))")
                .addPositionalValues(r.id(), r.gateway(), r.urlPattern(),
                        subjectKind, subjectValue, r.allow())
                .build()), "upsert " + r.id());
    }

    @Override
    public Mono<Void> delete(String id) {
        return run(() -> session().execute(SimpleStatement.builder(
                "DELETE FROM gateway_route_access WHERE id = ?")
                .addPositionalValue(id).build()), "delete " + id);
    }

    @Override
    public Flux<String> listIds() {
        return runRead(this::queryAllIds, "listIds");
    }

    private List<String> queryAllIds() {
        CqlSession s = session();
        if (s == null) return List.<String>of();
        List<String> ids = new ArrayList<>();
        ResultSet rs = s.execute(SimpleStatement.builder(
                "SELECT id FROM gateway_route_access").build());
        for (Row row : rs) {
            Object id = row.getObject("id");
            if (id != null) {
                ids.add(id.toString());
            }
        }
        return ids;
    }

    /**
     * Best-effort READ variant of {@link #run}: runs the blocking Cassandra query on
     * a bounded-elastic scheduler (never blocks the WebFlux event loop) and swallows
     * ANY failure into an EMPTY {@link Flux} (logged). A disabled mirror or an
     * absent/unreachable/erroring Cassandra therefore yields NO ids — the caller
     * (the G4 delete-reconcile) treats an empty read as "do not prune", so a failed
     * enumeration can never drive a mass-eviction.
     */
    private Flux<String> runRead(Supplier<List<String>> query, String what) {
        if (!enabled) return Flux.empty();
        return Mono.fromSupplier(query)
                .subscribeOn(Schedulers.boundedElastic())
                .flatMapMany(Flux::fromIterable)
                .onErrorResume(e -> {
                    log.warn("[route-mirror] best-effort {} failed: {} (no prune this pass)",
                            what, e.toString());
                    return Flux.empty();
                });
    }

    /**
     * Wrap the blocking Cassandra driver call on a bounded-elastic scheduler (so
     * it never blocks the WebFlux event loop) and swallow any failure — the
     * authoritative Postgres write already succeeded; the gateways will re-derive
     * from Postgres on their next refresh.
     */
    private Mono<Void> run(Runnable op, String what) {
        if (!enabled) return Mono.empty();
        return Mono.<Void>fromRunnable(op)
                .subscribeOn(Schedulers.boundedElastic())
                .onErrorResume(e -> {
                    log.warn("[route-mirror] best-effort {} failed: {} (gateways will still pick up the "
                            + "change from Postgres on their next refresh)", what, e.toString());
                    return Mono.empty();
                })
                .then();
    }

    @PreDestroy
    void close() {
        CqlSession s = session;
        if (s != null) {
            try { s.close(); } catch (Exception ignore) { } //NOPMD EmptyCatchBlock - best-effort close
        }
    }
}
