package net.hugmesh.adminbff.provision;

import com.datastax.oss.driver.api.core.CqlSession;
import com.datastax.oss.driver.api.core.cql.SimpleStatement;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;
import net.hugmesh.adminbff.cassandra.CassandraSessionFactory;

import jakarta.annotation.PreDestroy;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;

/**
 * Records the {@code token-hash -> {localpart, platform, kind}} row at homeserver
 * token MINT time so the gateway's {@code HomeserverTokenRevocationFilter} can later
 * resolve an opaque homeserver bearer back to a localpart and deny it when revoked.
 *
 * <p>This is the admin-bff (brokered) write side: every brokered mint writes a row
 * with {@code kind=brokered} (vs {@code kind=personal} for the user-bff personal-
 * client mint), the discriminator that lets external-client revocation spare the
 * brokered token while still blocking native clients.
 *
 * <p>The Cassandra table {@code hugmesh_gateway.hs_tokens} is defined by gateway
 * migration 006 (CassandraSchemaMigrations):
 * <pre>{@code
 * CREATE TABLE hs_tokens (
 *   token_hash text PRIMARY KEY,
 *   localpart text,
 *   platform text,
 *   kind text,
 *   app_or_device_id text,
 *   minted_at timestamp
 * ) WITH default_time_to_live = 2592000
 * }</pre>
 *
 * <p>The CqlSession is built lazily (same pattern as {@link CassandraRouteMirror}) and
 * every write is wrapped on {@code boundedElastic} so the blocking driver call never
 * touches the WebFlux event loop. It is gated by {@code broker.hs-token-registry.enabled}
 * (default {@code false}); when disabled the write is logged and skipped so a
 * Cassandra-less dev/test/CI run boots clean. It NEVER hard-fails — a recording failure
 * is swallowed by {@link #recordBrokered} so the mint still returns the token to the
 * caller.
 */
@Component
public class HsTokenRegistry {

    private static final Logger log = LoggerFactory.getLogger(HsTokenRegistry.class);

    public static final String KIND_BROKERED = "brokered";

    private final boolean enabled;
    private final String contactPoint;
    private final String localDc;
    private final String keyspace;
    private final CassandraSessionFactory sessionFactory;
    private volatile CqlSession session;

    public HsTokenRegistry(
            @Value("${broker.hs-token-registry.enabled:false}") boolean enabled,
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

    public boolean enabled() {
        return enabled;
    }

    /**
     * Record a freshly-minted brokered homeserver token. Best-effort: a recording
     * failure is swallowed so the mint still returns the token to the caller.
     *
     * @param accessToken the opaque homeserver access token (its SHA-256 hex is the key)
     * @param localpart   the homeserver localpart the token authenticates
     * @param platform    {@code matrix} or {@code mastodon}
     */
    public Mono<Void> recordBrokered(String accessToken, String localpart, String platform) {
        return doRecord(accessToken, localpart, platform, KIND_BROKERED)
                .onErrorResume(e -> {
                    log.warn("[hs-tokens] best-effort record for {}:{} failed (token still issued): {}",
                            platform, localpart, e.toString());
                    return Mono.empty();
                });
    }

    /**
     * Write one row to {@code hugmesh_gateway.hs_tokens}. The token is hashed
     * (SHA-256 hex) before storage — the gateway's filter does the same hash on the
     * incoming bearer so the lookup key matches. {@code app_or_device_id} is null for
     * brokered tokens (they have no device/app discriminator at mint time).
     *
     * <p>The blocking Cassandra driver call is dispatched on {@code boundedElastic} so
     * it never pins a WebFlux event-loop thread.
     */
    private Mono<Void> doRecord(String accessToken, String localpart, String platform, String kind) {
        if (accessToken == null || accessToken.isBlank() || localpart == null || localpart.isBlank()) {
            return Mono.empty();
        }
        if (!enabled) {
            log.debug("[hs-tokens] record STUBBED (broker.hs-token-registry.enabled=false): "
                    + "platform={} localpart={} kind={}", platform, localpart, kind);
            return Mono.empty();
        }
        // Hash the token and insert the record on boundedElastic (blocking Cassandra call).
        return Mono.<Void>fromRunnable(() -> insertTokenRecord(accessToken, localpart, platform, kind))
                .subscribeOn(Schedulers.boundedElastic());
    }

    /** Hash the token and execute the blocking Cassandra INSERT for the token record. */
    private void insertTokenRecord(String accessToken, String localpart, String platform, String kind) {
        String tokenHash = sha256Hex(accessToken);
        session().execute(SimpleStatement.builder(
                "INSERT INTO hs_tokens "
                + "(token_hash, localpart, platform, kind, app_or_device_id, minted_at) "
                + "VALUES (?, ?, ?, ?, ?, ?)")
                .addPositionalValues(tokenHash, localpart, platform, kind, null, Instant.now())
                .build());
        log.debug("[hs-tokens] recorded platform={} localpart={} kind={} hash={}...",
                platform, localpart, kind, tokenHash.substring(0, 8));
    }

    // ── Cassandra session (lazy, same pattern as CassandraRouteMirror) ────────

    private CqlSession session() {
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

    @PreDestroy
    void close() {
        CqlSession s = session;
        if (s != null) {
            try { s.close(); } catch (Exception ignore) { } //NOPMD EmptyCatchBlock - best-effort close
        }
    }

    // ── SHA-256 hex (mirrors HomeserverTokenRevocationFilter on the gateway) ──

    static String sha256Hex(String input) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] digest = md.digest(input.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder(digest.length * 2);
            for (byte b : digest) sb.append("%02x".formatted(b));
            return sb.toString();
        } catch (NoSuchAlgorithmException e) {
            // SHA-256 is guaranteed present in every Java runtime
            throw new IllegalStateException("SHA-256 not available", e);
        }
    }
}
