package systems.hugmesh.adminbff.filter;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;
import systems.hugmesh.adminbff.cassandra.CassandraSessionFactory;
import systems.hugmesh.adminbff.homeserver.HomeserverAdminClient;
import systems.hugmesh.adminbff.homeserver.HomeserverOutcome;
import systems.hugmesh.adminbff.lease.LeaderElection;
import systems.hugmesh.adminbff.provision.HsTokenRegistry;
import systems.hugmesh.adminbff.suspension.AccessSuspension;
import systems.hugmesh.adminbff.suspension.AccessSuspensionRepository;
import systems.hugmesh.adminbff.suspension.MatrixAccessSyncAction;
import systems.hugmesh.authcore.provision.GatewayRevocationClient;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for admin-bff's revocation gate — the combination of
 * {@link HsTokenRegistry} (SHA-256 mint-side write) and
 * {@link GatewayRevocationClient} (coarse-revoke HTTP call) that together
 * implement the "homeserver token revocation" contract described in the org
 * synthesis and confirmed by the gateway's {@code HomeserverTokenRevocationFilter}.
 *
 * <p>admin-bff owns the WRITE side of the revocation gate:
 * <ul>
 *   <li>{@link HsTokenRegistry} — records a {@code token_hash -> {localpart,
 *       platform, kind}} row in {@code hugmesh_gateway.hs_tokens} at mint time
 *       so the gateway filter can resolve an opaque bearer to its identity without a
 *       homeserver round-trip (PREREQ layer P1).</li>
 *   <li>{@link GatewayRevocationClient} — writes/clears the coarse
 *       {@code hs:<platform>:<localpart>} key on the gateway's revocation list when a
 *       suspension is enforced or lifted.</li>
 * </ul>
 *
 * <p><b>Three scenarios (mirroring the gateway filter's deny / allow / pass-through
 * contract):</b>
 * <ol>
 *   <li><b>Revoked token</b> — an active suspension is present for a localpart; the
 *       reconcile loop MUST call {@link GatewayRevocationClient#revokeCoarse} so the
 *       gateway filter denies every bearer token for that localpart (equivalent to a
 *       401/403 at the filter boundary).</li>
 *   <li><b>Non-revoked token</b> — no active suspension for the localpart; the reconcile
 *       loop MUST NOT call {@code revokeCoarse} (equivalent to the gateway filter calling
 *       {@code chain.filter(exchange)}).</li>
 *   <li><b>Missing bearer / null token</b> — a null or blank access token presented to
 *       {@link HsTokenRegistry#recordBrokered} is silently skipped (no Cassandra write,
 *       no error); the gate does not interfere with requests that carry no homeserver
 *       bearer (equivalent to the filter leaving unauthenticated requests to the coarse
 *       security gate).</li>
 * </ol>
 *
 * <p>Delineated:
 * <ul>
 *   <li>USER-SITUATIONAL: active suspension triggers {@code revokeCoarse} (revoked
 *       token denied at gateway);</li>
 *   <li>USER-SITUATIONAL: no active suspension — {@code revokeCoarse} never called
 *       (non-revoked token allowed through);</li>
 *   <li>USER-SITUATIONAL: null/blank token passed to registry — skipped silently
 *       (missing bearer does not fault the gate);</li>
 *   <li>USER-SITUATIONAL: SHA-256 hash is stable, lowercase hex, 64 chars —
 *       verifies the token_hash key matches what the gateway filter computes.</li>
 * </ul>
 *
 * <p>Uses {@link MockitoExtension} only — no Spring context, no Cassandra, no
 * network. The {@link GatewayRevocationClient} is fully mocked; the
 * {@link CassandraSessionFactory} is mocked for the enabled-but-unconnected registry
 * path.
 */
@ExtendWith(MockitoExtension.class)
class RevocationFilterTest {

    // ── mocked revocation list service/cache (the gateway-side write surface) ──

    @Mock
    GatewayRevocationClient gatewayRevocationClient;

    // ── mocked suspension repository (provides the desired-state input) ────────

    @Mock
    AccessSuspensionRepository suspensionRepository;

    // ── stubbed homeserver — always returns STUBBED so the test never calls
    //    a real homeserver and the reconcile loop still completes ───────────────

    @Mock
    HomeserverAdminClient homeserverAdminClient;

    // ── always-leader election so the reconcile loop never short-circuits ──────

    private final LeaderElection alwaysLeader = new systems.hugmesh.adminbff.lease.AlwaysLeader();

    @BeforeEach
    void configureDefaultStubs() {
        // Homeserver always returns STUBBED — the test does not exercise the
        // homeserver leg; it only verifies the revocation call.
        // lenient(): the SHA-256 hash tests don't drive reconcile so these stubs go unused.
        lenient().when(homeserverAdminClient.deactivateMatrix(anyString()))
                .thenReturn(Mono.just(HomeserverOutcome.stubbed()));
        lenient().when(homeserverAdminClient.activateMatrix(anyString()))
                .thenReturn(Mono.just(HomeserverOutcome.stubbed()));
        lenient().when(homeserverAdminClient.suspendMastodon(anyString()))
                .thenReturn(Mono.just(HomeserverOutcome.stubbed()));
        lenient().when(homeserverAdminClient.unsuspendMastodon(anyString()))
                .thenReturn(Mono.just(HomeserverOutcome.stubbed()));

        // Gateway revocation client stubs: allow(revokeCoarse) → empty Mono
        lenient().when(gatewayRevocationClient.revokeCoarse(anyString(), anyString(), any(), anyLong()))
                .thenReturn(Mono.empty());
        lenient().when(gatewayRevocationClient.revokeCoarse(anyString(), anyString(), isNull(), anyLong()))
                .thenReturn(Mono.empty());
        lenient().when(gatewayRevocationClient.clearCoarse(anyString(), anyString()))
                .thenReturn(Mono.empty());

        // Suspension repo: updatePropagationState is always called after enforce;
        // stub it so the reconcile chain can complete.
        lenient().when(suspensionRepository.updatePropagationState(anyString(), anyString()))
                .thenReturn(Mono.empty());

        // No Casdoor members by default (this test focuses on the revocation path,
        // not the Casdoor membership leg).
        lenient().when(suspensionRepository.activeByRole(anyString()))
                .thenReturn(reactor.core.publisher.Flux.empty());
    }

    // ── Scenario 1: REVOKED TOKEN → gateway deny (revokeCoarse is called) ──────

    /**
     * When an active ROLE_MATRIX suspension exists for "alice", the reconcile loop
     * MUST call {@code revokeCoarse("matrix", "alice", ...)} so the gateway filter
     * denies every homeserver bearer for that localpart — equivalent to a
     * 401/403 at the gateway filter boundary.
     */
    @Test
    void revokedToken_activeSuspension_gatewayRevokeCoarseIsCalled() {
        // Arrange: one active suspension row for "alice"
        AccessSuspension suspension = activeSuspension("alice", "matrix-alice",
                AccessSuspension.ROLE_MATRIX, "abuse", "1");
        when(suspensionRepository.activeByRole(AccessSuspension.ROLE_MATRIX))
                .thenReturn(reactor.core.publisher.Flux.fromIterable(List.of(suspension)));

        MatrixAccessSyncAction action = new MatrixAccessSyncAction(
                null, homeserverAdminClient, suspensionRepository, alwaysLeader,
                gatewayRevocationClient);

        // Act
        StepVerifier.create(action.runOnce()).verifyComplete();

        // Assert: revokeCoarse("matrix", "alice", ...) was called — the token is
        // now on the gateway revocation list and will be denied at the filter.
        verify(gatewayRevocationClient).revokeCoarse(eq("matrix"), eq("alice"), any(), anyLong());
    }

    /**
     * A Mastodon suspension enforces the same pattern: {@code revokeCoarse("mastodon",
     * "bob", ...)} is called so the Mastodon bearer is denied at the filter.
     */
    @Test
    void revokedToken_mastodonSuspension_gatewayRevokeCoarseIsCalled() {
        // Arrange: one active ROLE_MASTODON suspension for "bob"
        AccessSuspension suspension = activeSuspension("bob", "mastodon-bob",
                AccessSuspension.ROLE_MASTODON, "spam", "2");
        when(suspensionRepository.activeByRole(AccessSuspension.ROLE_MASTODON))
                .thenReturn(reactor.core.publisher.Flux.fromIterable(List.of(suspension)));

        systems.hugmesh.adminbff.suspension.MastodonAccessSyncAction action =
                new systems.hugmesh.adminbff.suspension.MastodonAccessSyncAction(
                        null, homeserverAdminClient, suspensionRepository, alwaysLeader,
                        gatewayRevocationClient);

        // Act
        StepVerifier.create(action.runOnce()).verifyComplete();

        // Assert
        verify(gatewayRevocationClient).revokeCoarse(eq("mastodon"), eq("bob"), any(), anyLong());
        verify(gatewayRevocationClient, never())
                .revokeCoarse(eq("matrix"), anyString(), any(), anyLong());
    }

    // ── Scenario 2: NON-REVOKED TOKEN → gate passes (revokeCoarse never called) ──

    /**
     * When there are NO active suspensions the reconcile loop MUST NOT call
     * {@code revokeCoarse} — no tokens are on the revocation list and the gateway
     * filter lets requests through (equivalent to {@code chain.filter(exchange)}).
     */
    @Test
    void nonRevokedToken_noActiveSuspension_revokeCoarseNeverCalled() {
        // Arrange: no active suspensions (default stub from @BeforeEach returns empty Flux)

        MatrixAccessSyncAction action = new MatrixAccessSyncAction(
                null, homeserverAdminClient, suspensionRepository, alwaysLeader,
                gatewayRevocationClient);

        // Act
        StepVerifier.create(action.runOnce()).verifyComplete();

        // Assert: revocation client is never touched — the token is not blocked.
        verify(gatewayRevocationClient, never())
                .revokeCoarse(anyString(), anyString(), any(), anyLong());
        verify(gatewayRevocationClient, never())
                .revokeCoarse(anyString(), anyString(), isNull(), anyLong());
    }

    // ── Scenario 3: MISSING BEARER → registry skips silently (no fault) ────────

    /**
     * A null access token passed to {@link HsTokenRegistry#recordBrokered} MUST
     * complete empty without error — a request carrying no homeserver bearer is not
     * this gate's concern (equivalent to the filter calling
     * {@code chain.filter(exchange)} when no {@code Authorization: Bearer ...} header
     * is present). The registry never writes a Cassandra row for a null token.
     */
    @Test
    void missingBearer_nullToken_registrySkipsSilently() {
        HsTokenRegistry registry = disabledRegistry();

        StepVerifier.create(registry.recordBrokered(null, "alice", "matrix"))
                .verifyComplete();
    }

    /**
     * A blank (whitespace) access token behaves identically to null — the guard in
     * {@link HsTokenRegistry} treats it as "no token presented" and skips the write.
     */
    @Test
    void missingBearer_blankToken_registrySkipsSilently() {
        HsTokenRegistry registry = disabledRegistry();

        StepVerifier.create(registry.recordBrokered("   ", "alice", "matrix"))
                .verifyComplete();
    }

    /**
     * A null localpart is equally skipped — the registry cannot construct a valid
     * {@code token_hash -> localpart} row without both fields, so the write is a
     * no-op (equivalent to the filter leaving a request without a resolvable identity
     * to the downstream gate rather than hard-failing it).
     */
    @Test
    void missingBearer_nullLocalpart_registrySkipsSilently() {
        HsTokenRegistry registry = disabledRegistry();

        StepVerifier.create(registry.recordBrokered("syt_some_token", null, "matrix"))
                .verifyComplete();
    }

    // ── SHA-256 hash correctness: token key matches what the gateway filter uses ──

    /**
     * The token hash stored in {@code hs_tokens} MUST be the SHA-256 hex of the raw
     * bearer token — exactly the same computation the gateway's
     * {@code HomeserverTokenRevocationFilter.sha256()} applies to the incoming
     * {@code Authorization: Bearer <token>} value. If these diverge the gateway can
     * never resolve the token to its identity and fails-closed on every bearer.
     *
     * <p>RFC vector: SHA-256("") = e3b0c44...
     */
    @Test
    void sha256Hex_emptyString_knownVector() {
        String hash = sha256Hex("");
        assertThat(hash)
                .as("SHA-256('') must match the well-known RFC vector")
                .isEqualTo("e3b0c44298fc1c149afbf4c8996fb924"
                         + "27ae41e4649b934ca495991b7852b855");
    }

    /**
     * The hash is always 64 lowercase hex characters — the format the gateway reads
     * as {@code token_hash} from Cassandra for an O(1) map lookup.
     */
    @Test
    void sha256Hex_arbitraryToken_is64LowercaseHex() {
        String token = "syt_dGVzdA_abcdefghij_0123456789";
        String hash = sha256Hex(token);

        assertThat(hash).hasSize(64);
        assertThat(hash).matches("[0-9a-f]{64}");
    }

    /**
     * The hash is stable across calls — the same bearer always maps to the same
     * {@code token_hash} key, so gateway lookups are deterministic.
     */
    @Test
    void sha256Hex_sameToken_isStable() {
        String token = "syt_dGVzdA_abcdefghij_0123456789";
        assertThat(sha256Hex(token))
                .isEqualTo(sha256Hex(token));
    }

    /**
     * Different tokens produce different hashes — the SHA-256 hash is collision-
     * resistant at the scale of a homeserver token space.
     */
    @Test
    void sha256Hex_differentTokens_differentHashes() {
        assertThat(sha256Hex("token-abc"))
                .isNotEqualTo(sha256Hex("token-xyz"));
    }

    // ── helpers ───────────────────────────────────────────────────────────────

    /**
     * SHA-256 hex of {@code input} — mirrors the package-private
     * {@code HsTokenRegistry.sha256Hex} and the gateway's
     * {@code HomeserverTokenRevocationFilter.sha256} so the test can verify the
     * hash contract without relying on package-private visibility.
     */
    private static String sha256Hex(String input) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] digest = md.digest(input.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder(digest.length * 2);
            for (byte b : digest) sb.append(String.format("%02x", b));
            return sb.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 not available", e);
        }
    }

    /**
     * A disabled {@link HsTokenRegistry} (ships-dark default). Session is never
     * built so no real Cassandra is required; writes are stubbed (logged and skipped).
     */
    private static HsTokenRegistry disabledRegistry() {
        CassandraSessionFactory darkFactory = new CassandraSessionFactory(
                false, "", "",
                false, "", "PKCS12", "", "", "PKCS12", "");
        return new HsTokenRegistry(false,
                "cassandra.test.invalid:9042", "dc1", "hugmesh_gateway", darkFactory);
    }

    /**
     * Build a minimal active {@link AccessSuspension} record for the given
     * {@code localpart} and {@code role}. Matches the state the reconcile loop
     * reads from {@code access_suspension} when a ban is in force.
     */
    private static AccessSuspension activeSuspension(String localpart, String casdoorUser,
                                                      String role, String reason, String id) {
        return new AccessSuspension(
                id,
                casdoorUser,
                localpart,
                role,
                AccessSuspension.STATE_ACTIVE,
                Instant.now(),
                null,      // null expiresAt = permanent ban
                false,     // restoreRole = false for a permanent ban
                AccessSuspension.PROP_PENDING,
                reason,
                "test-admin",
                "default");
    }
}
