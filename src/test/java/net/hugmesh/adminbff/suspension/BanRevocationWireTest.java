package net.hugmesh.adminbff.suspension;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.r2dbc.core.DatabaseClient;
import org.springframework.test.context.ActiveProfiles;
import reactor.core.publisher.Mono;
import net.hugmesh.adminbff.federation.FederationOverrideClearClient;
import net.hugmesh.adminbff.homeserver.HomeserverAdminClient;
import net.hugmesh.adminbff.lease.AlwaysLeader;
import net.hugmesh.authcore.provision.GatewayRevocationClient;

import java.time.Instant;
import java.time.temporal.ChronoUnit;

import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import net.hugmesh.adminbff.support.AdminBffPostgresTestSupport;

/**
 * SEC-09 Gap 2 — ban→revoke call path: verifies that when the reconcile loop enforces a
 * ROLE_MATRIX or ROLE_MASTODON suspension it also calls
 * {@link GatewayRevocationClient#revokeCoarse} with the correct platform and localpart,
 * and that the expiry action calls {@link GatewayRevocationClient#clearCoarse} on restore.
 *
 * <p>Uses a REAL H2 repository (from {@link TestDatabaseConfig}), a stubbed
 * {@link HomeserverAdminClient} (enabled=false), {@link AlwaysLeader}, and a MOCKED
 * {@link GatewayRevocationClient} to capture the call.
 *
 * <p>Delineated:
 * <ul>
 *   <li>USER-SITUATIONAL: active ROLE_MATRIX suspension triggers {@code revokeCoarse("matrix", ...)};</li>
 *   <li>USER-SITUATIONAL: active ROLE_MASTODON suspension triggers {@code revokeCoarse("mastodon", ...)};</li>
 *   <li>USER-SITUATIONAL: PROFILE suspension does NOT trigger revokeCoarse (no homeserver key);</li>
 *   <li>USER-SITUATIONAL: ROLE_MESH suspension does NOT trigger revokeCoarse either (no
 *       homeserver at all) but DOES trigger {@code revokeSubject} — for mesh that key plus
 *       the Casdoor role drop ARE the ban;</li>
 *   <li>USER-SITUATIONAL: expiry restore triggers {@code clearCoarse} for ROLE_MATRIX;</li>
 *   <li>USER-SITUATIONAL: expiry restore triggers {@code clearCoarse} for ROLE_MASTODON;</li>
 *   <li>USER-SITUATIONAL: PROFILE restore does NOT trigger clearCoarse;</li>
 *   <li>USER-SITUATIONAL: ROLE_MESH restore does NOT trigger clearCoarse.</li>
 * </ul>
 */
@SpringBootTest(classes = BanRevocationWireTest.Boot.class)
@ActiveProfiles("test")
class BanRevocationWireTest extends AdminBffPostgresTestSupport {

    @org.springframework.boot.SpringBootConfiguration
    @org.springframework.boot.autoconfigure.EnableAutoConfiguration
    static class Boot { }

    @Autowired DatabaseClient db;

    private final HomeserverAdminClient stubbedHomeserver =
            new HomeserverAdminClient(null, null, false);
    private final AlwaysLeader leader = new AlwaysLeader();

    @BeforeEach
    void clearTable() {
        db.sql("DELETE FROM access_suspension").fetch().rowsUpdated().block();
    }

    private AccessSuspensionRepository repo() {
        return new AccessSuspensionRepository(net.hugmesh.adminbff.testutil.R2dbcRepos.of(db, net.hugmesh.adminbff.suspension.AccessSuspensionRowRepository.class));
    }

    private GatewayRevocationClient mockGateway() {
        GatewayRevocationClient mock = mock(GatewayRevocationClient.class);
        when(mock.revokeCoarse(anyString(), anyString(), anyString(), anyLong()))
                .thenReturn(Mono.empty());
        when(mock.revokeCoarse(anyString(), anyString(), isNull(), anyLong()))
                .thenReturn(Mono.empty());
        // The SUBJECT revoke sits between the coarse revoke and the Casdoor role drop in
        // AbstractAccessSyncAction#enforceSuspension. It must be stubbed or the enforce
        // chain assembles a .then(null) and aborts into reconcile()'s onErrorResume — the
        // tick would still "succeed" while the trailing legs silently never ran, which for
        // the ROLE_MESH case below (where the subject revoke + role drop ARE the ban)
        // would make the test assert nothing.
        when(mock.revokeSubject(anyString(), anyString(), anyLong()))
                .thenReturn(Mono.empty());
        when(mock.revokeSubject(anyString(), isNull(), anyLong()))
                .thenReturn(Mono.empty());
        when(mock.clearCoarse(anyString(), anyString()))
                .thenReturn(Mono.empty());
        return mock;
    }

    private FederationOverrideClearClient mockFederationClear() {
        FederationOverrideClearClient mock = mock(FederationOverrideClearClient.class);
        when(mock.clearSource(anyString())).thenReturn(Mono.empty());
        return mock;
    }

    // ── reconcile: revokeCoarse on enforce ────────────────────────────────────

    @Test
    void matrix_ban_calls_revokeCoarse_matrix() {
        AccessSuspensionRepository repo = repo();
        repo.insertActive("hugmesh/alice", "alice",
                AccessSuspension.ROLE_MATRIX, null, false, "abuse", "admin", "default").block();

        GatewayRevocationClient gateway = mockGateway();
        MatrixAccessSyncAction action =
                new MatrixAccessSyncAction(null, stubbedHomeserver, repo, leader, gateway);
        action.runOnce().block();

        verify(gateway, atLeastOnce()).revokeCoarse(eq("matrix"), eq("alice"), anyString(), anyLong());
        verify(gateway, never()).revokeCoarse(eq("mastodon"), anyString(), anyString(), anyLong());
    }

    @Test
    void mastodon_ban_calls_revokeCoarse_mastodon() {
        AccessSuspensionRepository repo = repo();
        repo.insertActive("hugmesh/bob", "bob",
                AccessSuspension.ROLE_MASTODON, null, false, "spam", "admin", "default").block();

        GatewayRevocationClient gateway = mockGateway();
        MastodonAccessSyncAction action =
                new MastodonAccessSyncAction(null, stubbedHomeserver, repo, leader, gateway);
        action.runOnce().block();

        verify(gateway, atLeastOnce()).revokeCoarse(eq("mastodon"), eq("bob"), anyString(), anyLong());
        verify(gateway, never()).revokeCoarse(eq("matrix"), anyString(), anyString(), anyLong());
    }

    @Test
    void mastodon_ban_dottedLocalpart_revokesUnderTheMastodonFold_notTheMatrixForm() {
        // A1 (identity-key consistency): the stored suspension localpart is the matrixUser form
        // (keeps '.'), but the akkoma account + brokered token are keyed on the mastodonLocalpart
        // fold ('.'->'_', 30-cap) at mint. The effect legs MUST target the folded form or the real
        // account is never suspended AND the coarse gateway key never matches the recorded token.
        AccessSuspensionRepository repo = repo();
        repo.insertActive("hugmesh/alice.smith", "alice.smith",
                AccessSuspension.ROLE_MASTODON, null, false, "spam", "admin", "default").block();

        GatewayRevocationClient gateway = mockGateway();
        MastodonAccessSyncAction action =
                new MastodonAccessSyncAction(null, stubbedHomeserver, repo, leader, gateway);
        action.runOnce().block();

        // Coarse revoke key uses the MASTODON fold 'alice_smith', never the stored matrix form.
        verify(gateway, atLeastOnce()).revokeCoarse(eq("mastodon"), eq("alice_smith"), anyString(), anyLong());
        verify(gateway, never()).revokeCoarse(eq("mastodon"), eq("alice.smith"), anyString(), anyLong());
    }

    @Test
    void matrix_ban_dottedLocalpart_revokesUnderTheMatrixForm_unfolded() {
        // A1 counterpart: the tuwunel account IS the matrixUser form, so the Matrix effect leg must
        // NOT fold — the '.' is preserved (effectLocalpart is identity for Matrix).
        AccessSuspensionRepository repo = repo();
        repo.insertActive("hugmesh/alice.smith", "alice.smith",
                AccessSuspension.ROLE_MATRIX, null, false, "abuse", "admin", "default").block();

        GatewayRevocationClient gateway = mockGateway();
        MatrixAccessSyncAction action =
                new MatrixAccessSyncAction(null, stubbedHomeserver, repo, leader, gateway);
        action.runOnce().block();

        verify(gateway, atLeastOnce()).revokeCoarse(eq("matrix"), eq("alice.smith"), anyString(), anyLong());
    }

    @Test
    void mesh_ban_never_calls_revokeCoarse_butStillRevokesTheSubject() {
        // ROLE_MESH has NO homeserver and therefore no homeserver-minted bearer token, so
        // the coarse key hs:mesh:<localpart> would be a revocation row the gateway's
        // HomeserverTokenRevocationFilter can never match — 30 days of dead weight per ban.
        // MeshAccessSyncAction overrides that leg away. What DOES run is the subject
        // revoke: the user's in-flight custody JWT still carries ROLE_MESH for up to its
        // ~1 h lifetime, and that key is what makes the ban bite before the JWT expires.
        AccessSuspensionRepository repo = repo();
        repo.insertActive("hugmesh/mallory", "mallory",
                AccessSuspension.ROLE_MESH, null, false, "mesh-abuse", "admin", "default").block();

        GatewayRevocationClient gateway = mockGateway();
        MeshAccessSyncAction action =
                new MeshAccessSyncAction(null, stubbedHomeserver, repo, leader, gateway);
        action.runOnce().block();

        verify(gateway, never()).revokeCoarse(anyString(), anyString(), anyString(), anyLong());
        verify(gateway, atLeastOnce()).revokeSubject(eq("mallory"), eq("mesh-abuse"), anyLong());
    }

    @Test
    void mesh_restore_never_calls_clearCoarse() {
        // Symmetric to the enforce leg: no hs:mesh:* key was ever written, so the restore
        // path must not try to clear one (the expiry action's platform switch falls through
        // to its no-op default for any role that is neither ROLE_MATRIX nor ROLE_MASTODON).
        AccessSuspensionRepository repo = repo();
        repo.insertActive("hugmesh/oscar", "oscar",
                AccessSuspension.ROLE_MESH,
                Instant.now().minus(1, ChronoUnit.MINUTES), true, null, "admin", "default").block();

        GatewayRevocationClient gateway = mockGateway();
        SuspensionExpiryAction expiry =
                new SuspensionExpiryAction(null, stubbedHomeserver, repo, leader, gateway, mockFederationClear());
        expiry.runOnce().block();

        verify(gateway, never()).clearCoarse(anyString(), anyString());
    }

    @Test
    void noSuspensions_never_calls_revokeCoarse() {
        AccessSuspensionRepository repo = repo();
        // No suspension rows — nothing to enforce.

        GatewayRevocationClient gateway = mockGateway();
        MatrixAccessSyncAction action =
                new MatrixAccessSyncAction(null, stubbedHomeserver, repo, leader, gateway);
        action.runOnce().block();

        verify(gateway, never()).revokeCoarse(anyString(), anyString(), anyString(), anyLong());
    }

    // ── expiry restore: clearCoarse on restore ────────────────────────────────

    @Test
    void matrix_restore_calls_clearCoarse_matrix() {
        AccessSuspensionRepository repo = repo();
        repo.insertActive("hugmesh/carol", "carol",
                AccessSuspension.ROLE_MATRIX,
                Instant.now().minus(1, ChronoUnit.MINUTES), true, null, "admin", "default").block();

        GatewayRevocationClient gateway = mockGateway();
        SuspensionExpiryAction expiry =
                new SuspensionExpiryAction(null, stubbedHomeserver, repo, leader, gateway, mockFederationClear());
        expiry.runOnce().block();

        verify(gateway, atLeastOnce()).clearCoarse(eq("matrix"), eq("carol"));
        verify(gateway, never()).clearCoarse(eq("mastodon"), anyString());
    }

    @Test
    void mastodon_restore_calls_clearCoarse_mastodon() {
        AccessSuspensionRepository repo = repo();
        repo.insertActive("hugmesh/dave", "dave",
                AccessSuspension.ROLE_MASTODON,
                Instant.now().minus(1, ChronoUnit.MINUTES), true, null, "admin", "default").block();

        GatewayRevocationClient gateway = mockGateway();
        SuspensionExpiryAction expiry =
                new SuspensionExpiryAction(null, stubbedHomeserver, repo, leader, gateway, mockFederationClear());
        expiry.runOnce().block();

        verify(gateway, atLeastOnce()).clearCoarse(eq("mastodon"), eq("dave"));
        verify(gateway, never()).clearCoarse(eq("matrix"), anyString());
    }

    @Test
    void profile_restore_never_calls_clearCoarse() {
        // PROFILE suspensions have no homeserver platform key.
        AccessSuspensionRepository repo = repo();
        repo.insertActive("hugmesh/eve", "eve",
                AccessSuspension.ROLE_PROFILE,
                Instant.now().minus(1, ChronoUnit.MINUTES), true, null, "admin", "default").block();

        GatewayRevocationClient gateway = mockGateway();
        SuspensionExpiryAction expiry =
                new SuspensionExpiryAction(null, stubbedHomeserver, repo, leader, gateway, mockFederationClear());
        expiry.runOnce().block();

        verify(gateway, never()).clearCoarse(anyString(), anyString());
    }

    @Test
    void permanentBan_never_calls_clearCoarse() {
        // Permanent ban (expires_at NULL, restore_role=false) — excluded from dueForRestore.
        AccessSuspensionRepository repo = repo();
        repo.insertActive("hugmesh/frank", "frank",
                AccessSuspension.ROLE_MATRIX, null, false, "permanent", "admin", "default").block();

        GatewayRevocationClient gateway = mockGateway();
        SuspensionExpiryAction expiry =
                new SuspensionExpiryAction(null, stubbedHomeserver, repo, leader, gateway, mockFederationClear());
        expiry.runOnce().block();

        verify(gateway, never()).clearCoarse(anyString(), anyString());
    }
}
