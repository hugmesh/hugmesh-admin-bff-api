package net.hugmesh.adminbff.cassandra;

import com.datastax.oss.driver.api.core.CqlSessionBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;

/**
 * Shared, SHIPS-DARK hardening seam for the THREE classes that each build their
 * own {@link com.datastax.oss.driver.api.core.CqlSession CqlSession} lazily
 * ({@code CassandraRouteMirror}, {@code HsTokenRegistry},
 * {@code UrlRegistryRepository}). Construction is programmatic (the DataStax
 * {@code java-driver-core} is on the classpath WITHOUT spring-data-cassandra, and
 * {@code CassandraAutoConfiguration} is deliberately excluded in
 * {@code application.yml}), so the {@code spring.cassandra.*} username/password/ssl
 * keys are inert here — auth and TLS MUST be applied via the Java driver API.
 *
 * <p>This factory is the single chokepoint each of those three builders now calls
 * via {@link #harden(CqlSessionBuilder)} instead of triplicating the wiring. Both
 * the auth leg and the TLS leg are gated behind SEPARATE flags that DEFAULT OFF, so
 * merging this change is INERT: the produced session is byte-for-byte the prior
 * plaintext/no-auth session until an operator flips a flag. Flipping a hardening
 * flag never changes the existing connectivity ({@code app.mirror.cassandra.enabled}
 * / {@code broker.hs-token-registry.enabled}) semantics.
 *
 * <h2>Flags (all default OFF / blank — never in git)</h2>
 * <ul>
 *   <li>{@code app.mirror.cassandra.auth.enabled} (default {@code false}) — when
 *       true, applies {@code .withAuthCredentials(username, password)} (DataStax
 *       {@code PlainTextAuthProvider}) for Cassandra-native auth. The username and
 *       password come from {@code CASSANDRA_USERNAME} / {@code CASSANDRA_PASSWORD}
 *       env (ESO-synced Secret), referenced by {@code ${...:}} placeholders with
 *       EMPTY defaults — never hardcoded.</li>
 *   <li>{@code app.mirror.cassandra.ssl.enabled} (default {@code false}) — when
 *       true, applies {@code .withSslContext(SSLContext)} built from a PKCS12
 *       truststore (and, when client-auth is required, a PKCS12 keystore). Store
 *       PATHS mirror the {@code server.ssl} {@code /stores} layout; store PASSWORDS
 *       come from env with EMPTY defaults (loaded in-pod, never in git).</li>
 * </ul>
 *
 * <p>The factory NEVER hard-fails the caller's lazy build with a misconfiguration:
 * when a hardening leg is enabled but its inputs are missing/unreadable it throws an
 * {@link IllegalStateException} that surfaces at session-build time — the same place
 * the existing builders already surface connection errors — rather than silently
 * downgrading to plaintext (fail-closed once enabled).
 */
@Component
public class CassandraSessionFactory {

    private static final Logger log = LoggerFactory.getLogger(CassandraSessionFactory.class);

    // ── auth (default OFF; credentials via env / ESO Secret, blank-by-default) ──
    private final boolean authEnabled;
    private final String authUsername;
    private final String authPassword;

    // ── TLS (default OFF; store paths mounted, passwords via env, blank-by-default) ──
    private final boolean sslEnabled;
    private final String trustStorePath;
    private final String trustStoreType;
    private final String trustStorePassword;
    private final String keyStorePath;
    private final String keyStoreType;
    private final String keyStorePassword;

    public CassandraSessionFactory(
            @Value("${app.mirror.cassandra.auth.enabled:false}") boolean authEnabled,
            @Value("${app.mirror.cassandra.auth.username:}") String authUsername,
            @Value("${app.mirror.cassandra.auth.password:}") String authPassword,
            @Value("${app.mirror.cassandra.ssl.enabled:false}") boolean sslEnabled,
            @Value("${app.mirror.cassandra.ssl.trust-store:/stores/cassandra-truststore.p12}") String trustStorePath,
            @Value("${app.mirror.cassandra.ssl.trust-store-type:PKCS12}") String trustStoreType,
            @Value("${app.mirror.cassandra.ssl.trust-store-password:}") String trustStorePassword,
            @Value("${app.mirror.cassandra.ssl.key-store:}") String keyStorePath,
            @Value("${app.mirror.cassandra.ssl.key-store-type:PKCS12}") String keyStoreType,
            @Value("${app.mirror.cassandra.ssl.key-store-password:}") String keyStorePassword) {
        this.authEnabled = authEnabled;
        this.authUsername = authUsername;
        this.authPassword = authPassword;
        this.sslEnabled = sslEnabled;
        this.trustStorePath = trustStorePath;
        this.trustStoreType = trustStoreType;
        this.trustStorePassword = trustStorePassword;
        this.keyStorePath = keyStorePath;
        this.keyStoreType = keyStoreType;
        this.keyStorePassword = keyStorePassword;
    }

    public boolean authEnabled() {
        return authEnabled;
    }

    public boolean sslEnabled() {
        return sslEnabled;
    }

    /**
     * Apply the SHIPS-DARK auth + TLS legs (each independently gated, default OFF)
     * to a driver builder. With both flags OFF this is a no-op and the builder is
     * returned unchanged — identical to the pre-change plaintext/no-auth session.
     *
     * @param builder the per-class {@code CqlSession.builder()} chain (after
     *                contact-point / local-dc / keyspace have been set)
     * @return the same builder, hardened in place
     */
    public CqlSessionBuilder harden(CqlSessionBuilder builder) {
        if (authEnabled) {
            if (authUsername == null || authUsername.isBlank()) {
                throw new IllegalStateException(
                        "app.mirror.cassandra.auth.enabled=true but app.mirror.cassandra.auth.username is blank "
                        + "(set CASSANDRA_USERNAME via the ESO Secret — never hardcode)");
            }
            // PlainTextAuthProvider for Cassandra-native auth. Password may be empty
            // only if the operator deliberately runs a password-less role; we still
            // pass it through verbatim from env (never logged).
            builder = builder.withAuthCredentials(authUsername, authPassword == null ? "" : authPassword);
            log.info("[cassandra] native auth ENABLED (username from env; password never logged)");
        }
        if (sslEnabled) {
            builder = builder.withSslContext(buildSslContext());
            log.info("[cassandra] TLS ENABLED (truststore={}, client-cert={})",
                    trustStorePath, (keyStorePath != null && !keyStorePath.isBlank()) ? "present" : "none");
        }
        return builder;
    }

    /**
     * Build a JSSE {@link SSLContext} from the PKCS12 truststore (server-cert
     * verification) and, when a keystore path is configured, a PKCS12 keystore
     * (mutual-TLS client cert). Uses standard JSSE only — no app-side reflection —
     * so it needs no extra GraalVM native hints beyond the JDK metadata the parent
     * {@code add-reachability-metadata} already supplies.
     */
    private SSLContext buildSslContext() {
        if (trustStorePath == null || trustStorePath.isBlank()) {
            throw new IllegalStateException(
                    "app.mirror.cassandra.ssl.enabled=true but app.mirror.cassandra.ssl.trust-store is blank");
        }
        try {
            TrustManagerFactory tmf = TrustManagerFactory.getInstance(
                    TrustManagerFactory.getDefaultAlgorithm());
            tmf.init(loadStore(trustStorePath, trustStoreType, trustStorePassword));

            KeyManagerFactory kmf = null;
            if (keyStorePath != null && !keyStorePath.isBlank()) {
                kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
                KeyStore ks = loadStore(keyStorePath, keyStoreType, keyStorePassword);
                kmf.init(ks, (keyStorePassword == null ? "" : keyStorePassword).toCharArray());
            }

            SSLContext ctx = SSLContext.getInstance("TLS");
            ctx.init(kmf == null ? null : kmf.getKeyManagers(), tmf.getTrustManagers(), null);
            return ctx;
        } catch (RuntimeException e) {
            throw e;
        } catch (Exception e) {
            throw new IllegalStateException("[cassandra] failed to build TLS SSLContext: " + e, e);
        }
    }

    private static KeyStore loadStore(String path, String type, String password) throws Exception {
        Path p = Path.of(path);
        if (!Files.isReadable(p)) {
            throw new IllegalStateException("[cassandra] store not readable: " + path
                    + " (mount the PKCS12 store into the pod; never commit it to git)");
        }
        KeyStore store = KeyStore.getInstance(type == null || type.isBlank() ? "PKCS12" : type);
        try (InputStream in = Files.newInputStream(p)) {
            store.load(in, (password == null ? "" : password).toCharArray());
        }
        return store;
    }
}
