package net.hugmesh.adminbff.provision;

import org.junit.jupiter.api.Test;
import reactor.test.StepVerifier;
import net.hugmesh.adminbff.cassandra.CassandraSessionFactory;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for {@link HsTokenRegistry}.
 *
 * <p>Delineated:
 * <ul>
 *   <li>USER-SITUATIONAL: disabled registry skips writes (no Cassandra needed);</li>
 *   <li>USER-SITUATIONAL: blank/null inputs are silently skipped;</li>
 *   <li>USER-SITUATIONAL: SHA-256 hash is stable and lowercase-hex;</li>
 *   <li>USER-SITUATIONAL: enabled registry stub (no live Cassandra) surfaces the driver
 *       error and best-effort swallows it (recordBrokered completes empty, not error).</li>
 * </ul>
 *
 * <p>No live Cassandra is needed for any of these tests — the disabled path never builds
 * a session, and the enabled path is exercised only to verify error-swallowing (the driver
 * will fail to connect to the dummy address; that's exactly the condition we want to prove
 * is non-fatal to the caller).
 */
class HsTokenRegistryTest {

    /** Default-OFF hardening factory: auth + TLS both disabled (ships-dark default). */
    private static CassandraSessionFactory darkFactory() {
        return new CassandraSessionFactory(
                false, "", "",                 // auth: disabled, blank creds
                false, "", "PKCS12", "", "", "PKCS12", "");  // ssl: disabled, blank stores
    }

    private static HsTokenRegistry disabled() {
        return new HsTokenRegistry(false,
                "cassandra.test.invalid:9042", "dc1", "hugmesh_gateway", darkFactory());
    }

    private static HsTokenRegistry enabled() {
        // Points at a non-existent host — the driver error is the test vector for
        // best-effort swallowing. Session is built lazily, so constructing is safe.
        return new HsTokenRegistry(true,
                "127.0.0.1:19999", "dc1", "hugmesh_gateway", darkFactory());
    }

    // ── disabled (stub) path ───────────────────────────────────────────────────

    @Test
    void disabled_recordBrokered_completesEmpty_noError() {
        HsTokenRegistry registry = disabled();
        StepVerifier.create(registry.recordBrokered("some-token", "alice", "matrix"))
                .verifyComplete();
    }

    @Test
    void disabled_recordBrokered_nullToken_completesEmpty() {
        HsTokenRegistry registry = disabled();
        StepVerifier.create(registry.recordBrokered(null, "alice", "matrix"))
                .verifyComplete();
    }

    @Test
    void disabled_recordBrokered_blankToken_completesEmpty() {
        HsTokenRegistry registry = disabled();
        StepVerifier.create(registry.recordBrokered("   ", "alice", "matrix"))
                .verifyComplete();
    }

    @Test
    void disabled_recordBrokered_nullLocalpart_completesEmpty() {
        HsTokenRegistry registry = disabled();
        StepVerifier.create(registry.recordBrokered("token", null, "matrix"))
                .verifyComplete();
    }

    @Test
    void disabled_isNotEnabled() {
        assertThat(disabled().enabled()).isFalse();
    }

    @Test
    void enabled_isEnabled() {
        assertThat(enabled().enabled()).isTrue();
    }

    // ── SHA-256 helper ─────────────────────────────────────────────────────────

    @Test
    void sha256Hex_isStableAndLowercaseHex() {
        // SHA-256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        String hash = HsTokenRegistry.sha256Hex("");
        assertThat(hash).hasSize(64);
        assertThat(hash).matches("[0-9a-f]+");
        assertThat(hash).isEqualTo("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    }

    @Test
    void sha256Hex_differentInputs_differentHashes() {
        String h1 = HsTokenRegistry.sha256Hex("token-abc");
        String h2 = HsTokenRegistry.sha256Hex("token-xyz");
        assertThat(h1).isNotEqualTo(h2);
    }

    @Test
    void sha256Hex_sameInput_stableOutput() {
        String token = "syt_dGVzdA_abcdefghij_0123456789";
        assertThat(HsTokenRegistry.sha256Hex(token))
                .isEqualTo(HsTokenRegistry.sha256Hex(token));
    }

    // ── enabled path: Cassandra unreachable → best-effort swallow ─────────────

    @Test
    void enabled_cassandraUnreachable_recordBrokered_completesEmpty_bestEffort() {
        // The driver will fail to connect to 127.0.0.1:19999. The best-effort
        // onErrorResume in recordBrokered must swallow it and return Mono.empty(),
        // never propagating the error to the caller (the mint must succeed regardless).
        HsTokenRegistry registry = enabled();
        StepVerifier.create(registry.recordBrokered("syt_token_abc", "alice", "matrix"))
                .verifyComplete();
    }
}
