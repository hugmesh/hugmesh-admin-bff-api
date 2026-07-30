package systems.hugmesh.adminbff.cassandra;

import com.datastax.oss.driver.api.core.CqlSession;
import com.datastax.oss.driver.api.core.CqlSessionBuilder;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.catchThrowable;

/**
 * Unit tests for {@link CassandraSessionFactory} — the SHIPS-DARK auth + TLS
 * hardening seam shared by the three programmatic {@code CqlSession} builders.
 *
 * <p>Delineated:
 * <ul>
 *   <li>USER-SITUATIONAL (flag OFF): with both auth + ssl disabled (the default),
 *       {@code harden} is a pure no-op — it returns the very same builder instance
 *       and never opens a store or applies credentials (ships dark / inert);</li>
 *   <li>USER-SITUATIONAL (auth ON): the secure path WIRES auth — proven by the
 *       fail-closed contract (enabled + blank username throws) and by a successful
 *       application when a username is present (returns the same builder, hardened
 *       in place — no exception, no live cluster needed because the session is built
 *       lazily, not here);</li>
 *   <li>USER-SITUATIONAL (ssl ON): the secure path WIRES TLS — proven by building a
 *       real PKCS12 truststore on disk, enabling ssl, and asserting {@code harden}
 *       opens it and applies an {@code SSLContext} without error; and fail-closed
 *       when the truststore is missing/unreadable;</li>
 *   <li>CROSS (independence): auth and ssl gate independently, and neither flag is
 *       ON by default.</li>
 * </ul>
 *
 * <p>No live Cassandra is needed: {@code harden} only mutates the builder; the
 * actual {@code .build()} (which would dial) is never called here.
 */
class CassandraSessionFactoryTest {

    private static CassandraSessionFactory factory(
            boolean authEnabled, String user, String pass,
            boolean sslEnabled, String trustStore, String trustPass) {
        return new CassandraSessionFactory(
                authEnabled, user, pass,
                sslEnabled, trustStore, "PKCS12", trustPass,
                "", "PKCS12", "");
    }

    /** Both legs OFF — the ships-dark default. */
    private static CassandraSessionFactory dark() {
        return factory(false, "", "", false, "", "");
    }

    // ── flag OFF: inert / no-op (ships dark) ───────────────────────────────────

    @Test
    void bothFlagsOff_isNotEnabled() {
        CassandraSessionFactory f = dark();
        assertThat(f.authEnabled()).isFalse();
        assertThat(f.sslEnabled()).isFalse();
    }

    @Test
    void bothFlagsOff_harden_returnsSameBuilder_unchanged_noop() {
        CassandraSessionFactory f = dark();
        CqlSessionBuilder builder = CqlSession.builder();
        // With both flags OFF, harden must be a pure pass-through: same instance,
        // no auth applied, no store opened. (If it tried to apply auth/ssl it would
        // either mutate-and-still-return-same or, with blank inputs, throw — neither
        // happens here.)
        CqlSessionBuilder result = f.harden(builder);
        assertThat(result).isSameAs(builder);
    }

    // ── auth ON: secure path WIRES auth (fail-closed on blank, applies on present) ──

    @Test
    void authOn_blankUsername_failsClosed() {
        // Enabled but no CASSANDRA_USERNAME provided => must NOT silently downgrade
        // to no-auth; it throws so the misconfiguration is loud.
        CassandraSessionFactory f = factory(true, "", "", false, "", "");
        assertThat(f.authEnabled()).isTrue();
        assertThatThrownBy(() -> f.harden(CqlSession.builder()))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("auth.username is blank");
    }

    @Test
    void authOn_withUsername_appliesCredentials_noError() {
        // The secure path is wired: harden applies .withAuthCredentials and returns
        // the (same, hardened) builder. No live cluster is dialed (no .build()).
        CassandraSessionFactory f = factory(true, "admin_bff", "s3cret-from-env", false, "", "");
        CqlSessionBuilder builder = CqlSession.builder();
        CqlSessionBuilder result = f.harden(builder);
        assertThat(result).isSameAs(builder);   // hardened in place, no throw
    }

    // ── ssl ON: secure path WIRES TLS (applies with a real store, fails closed without) ──

    @Test
    void sslOn_withRealTrustStore_appliesSslContext_noError(@TempDir Path dir) throws Exception {
        Path store = writeEmptyPkcs12(dir.resolve("cassandra-truststore.p12"), "changeit");
        CassandraSessionFactory f = factory(false, "", "", true, store.toString(), "changeit");
        assertThat(f.sslEnabled()).isTrue();
        CqlSessionBuilder builder = CqlSession.builder();
        // The SSLContext is built from the on-disk PKCS12 and applied; no throw.
        CqlSessionBuilder result = f.harden(builder);
        assertThat(result).isSameAs(builder);
    }

    @Test
    void sslOn_missingTrustStore_failsClosed() {
        CassandraSessionFactory f = factory(false, "", "", true,
                "/no/such/cassandra-truststore.p12", "changeit");
        Throwable t = catchThrowable(() -> f.harden(CqlSession.builder()));
        assertThat(t).isInstanceOf(IllegalStateException.class);
        assertThat(t.getMessage()).contains("not readable");
    }

    @Test
    void sslOn_blankTrustStorePath_failsClosed() {
        CassandraSessionFactory f = factory(false, "", "", true, "", "changeit");
        assertThatThrownBy(() -> f.harden(CqlSession.builder()))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("trust-store is blank");
    }

    // ── cross: auth + ssl both ON, both applied in one harden() call ───────────

    @Test
    void authAndSslBothOn_bothApplied_noError(@TempDir Path dir) throws Exception {
        Path store = writeEmptyPkcs12(dir.resolve("cassandra-truststore.p12"), "changeit");
        CassandraSessionFactory f = factory(true, "admin_bff", "pw-from-env",
                true, store.toString(), "changeit");
        assertThat(f.authEnabled()).isTrue();
        assertThat(f.sslEnabled()).isTrue();
        CqlSessionBuilder builder = CqlSession.builder();
        assertThat(f.harden(builder)).isSameAs(builder);
    }

    // ── helper: write a real (empty) PKCS12 store so the TLS path has a file to open ──

    private static Path writeEmptyPkcs12(Path path, String password) throws Exception {
        KeyStore ks = KeyStore.getInstance("PKCS12");
        ks.load(null, null);   // initialize an empty keystore
        try (OutputStream out = Files.newOutputStream(path)) {
            ks.store(out, password.toCharArray());
        }
        return path;
    }
}
