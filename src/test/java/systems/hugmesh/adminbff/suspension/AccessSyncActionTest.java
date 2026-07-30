package systems.hugmesh.adminbff.suspension;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.r2dbc.core.DatabaseClient;
import org.springframework.test.context.ActiveProfiles;
import reactor.core.publisher.Mono;
import systems.hugmesh.authcore.casdoor.CasdoorAdminClient;
import systems.hugmesh.adminbff.homeserver.HomeserverAdminClient;
import systems.hugmesh.adminbff.homeserver.HomeserverOutcome;
import systems.hugmesh.adminbff.lease.AlwaysLeader;
import systems.hugmesh.adminbff.lease.LeaderElection;
import systems.hugmesh.authcore.provision.GatewayRevocationClient;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import systems.hugmesh.adminbff.support.AdminBffPostgresTestSupport;

/**
 * The single-writer reconcile + expiry behaviour of the access_suspension loop,
 * over a REAL H2 repository + a mocked {@link CasdoorAdminClient} + the gated
 * {@link HomeserverAdminClient} stub-seam (enabled=false → STUBBED) + AlwaysLeader.
 *
 * <p>Methods call {@code runOnce()} directly — outside the Spring AOP proxy the
 * {@code @CircuitBreaker} annotation is a no-op, so the reconcile body runs straight.
 */
@SpringBootTest(classes = AccessSyncActionTest.Boot.class)
@ActiveProfiles("test")
class AccessSyncActionTest extends AdminBffPostgresTestSupport {

    // @SpringBootConfiguration + @EnableAutoConfiguration WITHOUT @ComponentScan: the
    // actions are constructed by hand in each test, so we deliberately do NOT scan
    // the suspension package (which would pull the @Service graph + its cross-package
    // HomeserverAdminClient/LeaderElection beans). Only the H2 DatabaseClient (from
    // TestDatabaseConfig) is needed.
    @org.springframework.boot.SpringBootConfiguration
    @org.springframework.boot.autoconfigure.EnableAutoConfiguration
    static class Boot { }

    @Autowired DatabaseClient db;

    private final HomeserverAdminClient stubbedHomeserver =
            new HomeserverAdminClient(null, null, false); // enabled=false → all calls STUBBED
    private final LeaderElection leader = new AlwaysLeader();
    /** Disabled GatewayRevocationClient — never dials the gateway in unit tests. */
    private final GatewayRevocationClient noopGateway =
            new GatewayRevocationClient(false, "http://localhost");
    /** Disabled federation-override clear — gate off → clearSource is a no-op (no dial). */
    private final systems.hugmesh.adminbff.federation.FederationOverrideClearClient noopFederationClear =
            new systems.hugmesh.adminbff.federation.FederationOverrideClearClient(
                    null, false, () -> Mono.error(new IllegalStateException("token never minted when gate off")));

    private AccessSuspensionRepository repo() {
        return new AccessSuspensionRepository(systems.hugmesh.adminbff.testutil.R2dbcRepos.of(db, systems.hugmesh.adminbff.suspension.AccessSuspensionRowRepository.class));
    }

    @Test
    void concurrentGrantThenBan_selfHeals_loopDropsTheReGrantedRole() {
        AccessSuspensionRepository repo = repo();
        // Desired state: alice is banned from ROLE_MATRIX.
        repo.insertActive("hugmesh/alice", "alice",
                AccessSuspension.ROLE_MATRIX, null, false, "abuse", "admin", "default").block();

        CasdoorAdminClient casdoor = mock(CasdoorAdminClient.class);
        when(casdoor.organization()).thenReturn("hugmesh");
        // A concurrent grant clobbered alice BACK into the role; bob is a legit member.
        when(casdoor.getRoleMembers(AccessSuspension.ROLE_MATRIX))
                .thenReturn(Mono.just(List.of("hugmesh/alice", "hugmesh/bob")));
        when(casdoor.removeUserFromRole(eq(AccessSuspension.ROLE_MATRIX), eq("hugmesh/alice")))
                .thenReturn(Mono.empty());

        MatrixAccessSyncAction action =
                new MatrixAccessSyncAction(casdoor, stubbedHomeserver, repo, leader, noopGateway);
        action.runOnce().block();

        // The loop is the single writer: it re-removes the clobbered-in role for the
        // banned user (self-heal). It never removes bob (not suspended).
        verify(casdoor, times(1)).removeUserFromRole(AccessSuspension.ROLE_MATRIX, "hugmesh/alice");
        verify(casdoor, never()).removeUserFromRole(AccessSuspension.ROLE_MATRIX, "hugmesh/bob");

        // propagation_state advanced off 'pending' (here -> 'pending' since the
        // homeserver leg is stubbed; the role drop still happened).
        AccessSuspension after = repo.findActive("hugmesh/alice", AccessSuspension.ROLE_MATRIX).block();
        org.assertj.core.api.Assertions.assertThat(after).isNotNull();
        org.assertj.core.api.Assertions.assertThat(after.propagationState())
                .isEqualTo(AccessSuspension.PROP_PENDING); // stubbed homeserver
    }

    @Test
    void enforceSuspension_normalizesCasdoorUserToBareUsername_forSubjectRevoke() {
        AccessSuspensionRepository repo = repo();
        // The stored casdoorUser is the free-text admin-typed ban target (SuspensionService
        // javadoc: bare username / provider:handle / org/username), NOT the bare Casdoor
        // username the gateway's RevocationGatewayFilter matches the JWT sub against.
        repo.insertActive("google:Alice.Smith@x.com", "alice.smith",
                AccessSuspension.ROLE_MATRIX, null, false, "abuse", "admin", "default").block();

        CasdoorAdminClient casdoor = mock(CasdoorAdminClient.class);
        when(casdoor.organization()).thenReturn("hugmesh");
        when(casdoor.getRoleMembers(AccessSuspension.ROLE_MATRIX)).thenReturn(Mono.just(List.of()));
        when(casdoor.removeUserFromRole(eq(AccessSuspension.ROLE_MATRIX), eq("hugmesh/alice.smith")))
                .thenReturn(Mono.empty());

        GatewayRevocationClient gateway = mock(GatewayRevocationClient.class);
        when(gateway.revokeCoarse(anyString(), anyString(), any(), anyLong())).thenReturn(Mono.empty());
        when(gateway.revokeSubject(anyString(), any(), anyLong())).thenReturn(Mono.empty());

        MatrixAccessSyncAction action =
                new MatrixAccessSyncAction(casdoor, stubbedHomeserver, repo, leader, gateway);
        action.runOnce().block();

        // usernameOf(google, "Alice.Smith@x.com") lowercases + strips the "@..." tail — the
        // same fold AdminController#revokeOnDisable already applies before writing the
        // subject: key, so the gateway's match key (jwt sub) actually lines up.
        verify(gateway, times(1)).revokeSubject(eq("alice.smith"), eq("abuse"), eq(3_600L));
        // userIdFor applies the SAME normalization before the Casdoor role-drop leg —
        // without it, removeUserFromRole would be called with the never-matching
        // "hugmesh/google:Alice.Smith@x.com" and silently no-op forever (the role
        // membership list only ever contains "hugmesh/alice.smith").
        verify(casdoor, times(1)).removeUserFromRole(AccessSuspension.ROLE_MATRIX, "hugmesh/alice.smith");
    }

    @Test
    void enforceSuspension_stripsAtTail_forNonGoogleProvider_casdoorUsernameOf() {
        // auth-core 2.3.4 (PR #33) fixed CasdoorAdminClient.usernameOf to strip the
        // "@..." tail for EVERY provider, not just "google". Before that fix, a
        // provider:handle input like "casdoor:carol@example.org" (a first-class shape,
        // see SuspensionService#localpartSeed) would NOT have its "@..." tail stripped
        // by AbstractAccessSyncAction#casdoorUsernameOf (it delegates straight to
        // CasdoorAdminClient.usernameOf(provider, handle)), producing the wrong,
        // never-matching subject/member id. Mirrors
        // enforceSuspension_normalizesCasdoorUserToBareUsername_forSubjectRevoke above,
        // but with provider="casdoor" instead of "google".
        AccessSuspensionRepository repo = repo();
        AccessSuspension inserted = repo.insertActive("casdoor:Carol@example.org", "carol",
                AccessSuspension.ROLE_MATRIX, null, false, "abuse", "admin", "default").block();

        CasdoorAdminClient casdoor = mock(CasdoorAdminClient.class);
        when(casdoor.organization()).thenReturn("hugmesh");
        when(casdoor.getRoleMembers(AccessSuspension.ROLE_MATRIX)).thenReturn(Mono.just(List.of()));
        when(casdoor.removeUserFromRole(eq(AccessSuspension.ROLE_MATRIX), eq("hugmesh/carol")))
                .thenReturn(Mono.empty());

        GatewayRevocationClient gateway = mock(GatewayRevocationClient.class);
        when(gateway.revokeCoarse(anyString(), anyString(), any(), anyLong())).thenReturn(Mono.empty());
        when(gateway.revokeSubject(anyString(), any(), anyLong())).thenReturn(Mono.empty());

        MatrixAccessSyncAction action =
                new MatrixAccessSyncAction(casdoor, stubbedHomeserver, repo, leader, gateway);
        action.runOnce().block();

        // usernameOf("casdoor", "Carol@example.org") must lowercase + strip the "@..."
        // tail exactly like it does for "google" — pre-fix (auth-core <=2.3.3) this
        // would revoke subject "carol@example.org" and target member id
        // "hugmesh/carol@example.org", neither of which the gateway/Casdoor role
        // membership ever matches.
        verify(gateway, times(1)).revokeSubject(eq("carol"), eq("abuse"), eq(3_600L));
        verify(casdoor, times(1)).removeUserFromRole(AccessSuspension.ROLE_MATRIX, "hugmesh/carol");

        // Test-isolation hygiene: this test class's DB is per-CLASS (PostgresTestSupport),
        // not per-method, and a permanent ban (no restore_role) is never otherwise
        // resolved. activeByRole(ROLE_MATRIX) sweeps in EVERY active row regardless of
        // which test inserted it, so a leftover row here — sorted first by casdoorUser
        // ("casdoor:..." < "google:..." < "hugmesh/...") — would be concatMap'd
        // ahead of any later test's own row and (being unstubbed there) abort that
        // later test's whole tick before it ever reaches its own assertion. CAS this
        // row to 'restored' now so it never leaks into a sibling test.
        repo.markRestored(inserted.id()).block();
    }

    // ── ROLE_MESH: the Casdoor-ONLY leg (no homeserver exists) ────────────────

    @Test
    void meshBan_dropsCasdoorRoleOnly_neverTouchesAnyHomeserver() {
        AccessSuspensionRepository repo = repo();
        // Desired state: mallory is banned from ROLE_MESH.
        AccessSuspension inserted = repo.insertActive("hugmesh/mallory", "mallory",
                AccessSuspension.ROLE_MESH, null, false, "mesh-abuse", "admin", "default").block();

        CasdoorAdminClient casdoor = mock(CasdoorAdminClient.class);
        when(casdoor.organization()).thenReturn("hugmesh");
        // A concurrent grant clobbered mallory BACK into the role; nolan is a legit member.
        when(casdoor.getRoleMembers(AccessSuspension.ROLE_MESH))
                .thenReturn(Mono.just(List.of("hugmesh/mallory", "hugmesh/nolan")));
        when(casdoor.removeUserFromRole(eq(AccessSuspension.ROLE_MESH), eq("hugmesh/mallory")))
                .thenReturn(Mono.empty());

        GatewayRevocationClient gateway = mock(GatewayRevocationClient.class);
        when(gateway.revokeSubject(anyString(), any(), anyLong())).thenReturn(Mono.empty());
        // A STRICT mock homeserver: any call at all would fail with an unstubbed-method
        // NPE, and the verifyNoInteractions below pins it explicitly.
        HomeserverAdminClient homeserver = mock(HomeserverAdminClient.class);

        MeshAccessSyncAction action =
                new MeshAccessSyncAction(casdoor, homeserver, repo, leader, gateway);
        action.runOnce().block();

        // The ban IS the Casdoor role drop: the loop re-removes the clobbered-in role for
        // the banned user (self-heal) and never removes the legit member.
        verify(casdoor, times(1)).removeUserFromRole(AccessSuspension.ROLE_MESH, "hugmesh/mallory");
        verify(casdoor, never()).removeUserFromRole(AccessSuspension.ROLE_MESH, "hugmesh/nolan");
        // The JWT leg still runs — a stale custody JWT still carries ROLE_MESH for up to
        // its ~1 h lifetime, so the subject key is what makes the ban bite immediately.
        verify(gateway, times(1)).revokeSubject(eq("mallory"), eq("mesh-abuse"), eq(3_600L));
        // ... but NO homeserver leg exists for mesh (neither the suspend on enforce nor
        // the activate on the heal pass over the non-suspended member).
        org.mockito.Mockito.verifyNoInteractions(homeserver);
        // ... and NO coarse hs:mesh:<localpart> key is written: nothing mints a mesh
        // homeserver bearer, so that key could never match anything.
        verify(gateway, never()).revokeCoarse(anyString(), anyString(), any(), anyLong());

        // propagation_state settles on 'applied' (NOT 'pending'): there is no deferred
        // downstream effect to re-apply, so parking the row on 'pending' forever would be
        // a lie. This is the assertion that pins ok()-not-STUBBED in MeshAccessSyncAction.
        AccessSuspension after = repo.findActive("hugmesh/mallory", AccessSuspension.ROLE_MESH).block();
        org.assertj.core.api.Assertions.assertThat(after).isNotNull();
        org.assertj.core.api.Assertions.assertThat(after.propagationState())
                .isEqualTo(AccessSuspension.PROP_APPLIED);

        // Test-isolation hygiene (see enforceSuspension_stripsAtTail_...): the DB is
        // per-CLASS and a permanent ban is never otherwise resolved, so CAS this row to
        // 'restored' rather than letting activeByRole(ROLE_MESH) sweep it into a sibling.
        repo.markRestored(inserted.id()).block();
    }

    @Test
    void meshExpiry_tempBanAutoRestores_reAddsTheCasdoorRoleOnly() {
        AccessSuspensionRepository repo = repo();
        // A TIMED mesh suspension whose TTL has already passed, flagged to restore —
        // the temp-ban half of the vocabulary (mirrors expiry_autoRestoresAtTtl_... above).
        repo.insertActive("hugmesh/oscar", "oscar",
                AccessSuspension.ROLE_MESH,
                Instant.now().minus(5, ChronoUnit.MINUTES), true, null, "admin", "default").block();

        CasdoorAdminClient casdoor = mock(CasdoorAdminClient.class);
        when(casdoor.organization()).thenReturn("hugmesh");
        when(casdoor.addUserToRole(eq(AccessSuspension.ROLE_MESH), eq("hugmesh/oscar")))
                .thenReturn(Mono.empty());

        GatewayRevocationClient gateway = mock(GatewayRevocationClient.class);
        HomeserverAdminClient homeserver = mock(HomeserverAdminClient.class);

        SuspensionExpiryAction expiry =
                new SuspensionExpiryAction(casdoor, homeserver, repo, leader, gateway, noopFederationClear);
        expiry.runOnce().block();

        // The role came back at TTL — the restore path needs NO ROLE_MESH special-casing:
        // the expiry action's homeserver/coarse-key switches already fall through to their
        // no-op defaults for a role that is neither ROLE_MATRIX nor ROLE_MASTODON, and
        // reAddRole skips only PROFILE. This test pins that inherited behaviour so a later
        // edit to those switches cannot silently strand mesh temp-bans as permanent.
        verify(casdoor, times(1)).addUserToRole(AccessSuspension.ROLE_MESH, "hugmesh/oscar");
        org.mockito.Mockito.verifyNoInteractions(homeserver);
        verify(gateway, never()).clearCoarse(anyString(), anyString());
        // ... and the row is CASed active -> restored, so it is no longer in force.
        org.assertj.core.api.Assertions.assertThat(
                repo.findActive("hugmesh/oscar", AccessSuspension.ROLE_MESH).block()).isNull();
    }

    @Test
    void reconcile_withoutCasdoorClient_doesNotFail_stubSeamOnly() {
        AccessSuspensionRepository repo = repo();
        repo.insertActive("hugmesh/gina", "gina",
                AccessSuspension.ROLE_MASTODON, null, false, null, "admin", "default").block();
        // casdoor=null (casdoor.admin.enabled=false) — the loop still runs, only the
        // homeserver stub-seam executes, and it never throws.
        MastodonAccessSyncAction action =
                new MastodonAccessSyncAction(null, stubbedHomeserver, repo, leader, noopGateway);
        action.runOnce().block(); // completes without error
    }

    @Test
    void notLeader_skipsTheTick_neverWritesCasdoor() {
        AccessSuspensionRepository repo = repo();
        repo.insertActive("hugmesh/harry", "harry",
                AccessSuspension.ROLE_MATRIX, null, false, null, "admin", "default").block();

        CasdoorAdminClient casdoor = mock(CasdoorAdminClient.class);
        LeaderElection notLeader = new LeaderElection() {
            @Override public boolean isLeader() { return false; }
            @Override public String label() { return "test-not-leader"; }
        };
        MatrixAccessSyncAction action =
                new MatrixAccessSyncAction(casdoor, stubbedHomeserver, repo, notLeader, noopGateway);
        action.runOnce().block();

        // A non-leader replica never reads or writes Casdoor (single-writer invariant).
        verify(casdoor, never()).getRoleMembers(org.mockito.ArgumentMatchers.anyString());
        verify(casdoor, never()).removeUserFromRole(
                org.mockito.ArgumentMatchers.anyString(), org.mockito.ArgumentMatchers.anyString());
    }

    @Test
    void expiry_autoRestoresAtTtl_casThenReAddsRoleLast() {
        AccessSuspensionRepository repo = repo();
        // A timed suspension whose TTL has already passed, flagged to restore.
        AccessSuspension overdue = repo.insertActive("hugmesh/ivy", "ivy",
                AccessSuspension.ROLE_MASTODON,
                Instant.now().minus(5, ChronoUnit.MINUTES), true, null, "admin", "default").block();

        CasdoorAdminClient casdoor = mock(CasdoorAdminClient.class);
        when(casdoor.organization()).thenReturn("hugmesh");
        when(casdoor.addUserToRole(eq(AccessSuspension.ROLE_MASTODON), eq("hugmesh/ivy")))
                .thenReturn(Mono.empty());

        SuspensionExpiryAction expiry =
                new SuspensionExpiryAction(casdoor, stubbedHomeserver, repo, leader, noopGateway, noopFederationClear);
        expiry.runOnce().block();

        // The role was re-added (LAST, after the homeserver un-suspend leg) and the
        // row CASed active -> restored, so it is no longer active.
        verify(casdoor, times(1)).addUserToRole(AccessSuspension.ROLE_MASTODON, "hugmesh/ivy");
        org.assertj.core.api.Assertions.assertThat(
                repo.findActive("hugmesh/ivy", AccessSuspension.ROLE_MASTODON).block()).isNull();
    }

    @Test
    void expiry_normalizesProviderHandleCasdoorUser_forRoleReAdd() {
        AccessSuspensionRepository repo = repo();
        // Same free-text provider:handle input shape as the enforce-path test above,
        // now exercising the independent userIdFor copy in SuspensionExpiryAction.
        repo.insertActive("google:Bob.Jones@x.com", "bob.jones",
                AccessSuspension.ROLE_MASTODON,
                Instant.now().minus(5, ChronoUnit.MINUTES), true, null, "admin", "default").block();

        CasdoorAdminClient casdoor = mock(CasdoorAdminClient.class);
        when(casdoor.organization()).thenReturn("hugmesh");
        when(casdoor.addUserToRole(eq(AccessSuspension.ROLE_MASTODON), eq("hugmesh/bob.jones")))
                .thenReturn(Mono.empty());

        SuspensionExpiryAction expiry =
                new SuspensionExpiryAction(casdoor, stubbedHomeserver, repo, leader, noopGateway, noopFederationClear);
        expiry.runOnce().block();

        // Without the fix this would call addUserToRole("hugmesh/google:Bob.Jones@x.com"),
        // a member id the real Casdoor role never contains — restore would silently no-op.
        verify(casdoor, times(1)).addUserToRole(AccessSuspension.ROLE_MASTODON, "hugmesh/bob.jones");
    }

    @Test
    void expiry_mastodonRestore_unsuspendsHomeserverUnderTheFoldedLocalpart() {
        AccessSuspensionRepository repo = repo();
        // Stored localpart is the matrixUser form (dots preserved) — the akkoma account
        // is actually keyed under the Mastodon fold (dots -> '_'), same as the SUSPEND
        // leg (MastodonAccessSyncAction#effectLocalpart, PR #220).
        repo.insertActive("hugmesh/alice.smith", "alice.smith",
                AccessSuspension.ROLE_MASTODON,
                Instant.now().minus(5, ChronoUnit.MINUTES), true, null, "admin", "default").block();

        CasdoorAdminClient casdoor = mock(CasdoorAdminClient.class);
        when(casdoor.organization()).thenReturn("hugmesh");
        when(casdoor.addUserToRole(eq(AccessSuspension.ROLE_MASTODON), eq("hugmesh/alice.smith")))
                .thenReturn(Mono.empty());

        HomeserverAdminClient homeserver = mock(HomeserverAdminClient.class);
        when(homeserver.unsuspendMastodon(anyString())).thenReturn(Mono.just(HomeserverOutcome.ok()));

        SuspensionExpiryAction expiry =
                new SuspensionExpiryAction(casdoor, homeserver, repo, leader, noopGateway, noopFederationClear);
        expiry.runOnce().block();

        // The akkoma account was minted/keyed under the FOLDED localpart — the restore
        // leg must reactivate that SAME account, not a nonexistent "alice.smith" nickname.
        verify(homeserver, times(1)).unsuspendMastodon("alice_smith");
        verify(homeserver, never()).unsuspendMastodon("alice.smith");
    }

    @Test
    void expiry_mastodonRestore_clearsGatewayRevocationUnderTheFoldedLocalpart() {
        AccessSuspensionRepository repo = repo();
        repo.insertActive("hugmesh/alice.smith", "alice.smith",
                AccessSuspension.ROLE_MASTODON,
                Instant.now().minus(5, ChronoUnit.MINUTES), true, null, "admin", "default").block();

        CasdoorAdminClient casdoor = mock(CasdoorAdminClient.class);
        when(casdoor.organization()).thenReturn("hugmesh");
        when(casdoor.addUserToRole(eq(AccessSuspension.ROLE_MASTODON), eq("hugmesh/alice.smith")))
                .thenReturn(Mono.empty());

        GatewayRevocationClient gateway = mock(GatewayRevocationClient.class);
        when(gateway.clearCoarse(anyString(), anyString())).thenReturn(Mono.empty());

        SuspensionExpiryAction expiry =
                new SuspensionExpiryAction(casdoor, stubbedHomeserver, repo, leader, gateway, noopFederationClear);
        expiry.runOnce().block();

        // The SUSPEND leg wrote the coarse hs:mastodon:<localpart> key under the FOLDED
        // form (AbstractAccessSyncAction#enforceSuspension); the restore leg must clear
        // that SAME key, or the 30-day default TTL outlives the restore.
        verify(gateway, times(1)).clearCoarse("mastodon", "alice_smith");
        verify(gateway, never()).clearCoarse("mastodon", "alice.smith");
    }

    @Test
    void expiry_stripsAtTail_forNonGoogleProvider_casdoorUsernameOf() {
        // Same auth-core 2.3.4 (PR #33) fix as
        // enforceSuspension_stripsAtTail_forNonGoogleProvider_casdoorUsernameOf above,
        // now exercising SuspensionExpiryAction's independent casdoorUsernameOf/userIdFor
        // copy (this class does not share a base class with the access-sync actions).
        AccessSuspensionRepository repo = repo();
        repo.insertActive("casdoor:Dave@example.org", "dave",
                AccessSuspension.ROLE_MASTODON,
                Instant.now().minus(5, ChronoUnit.MINUTES), true, null, "admin", "default").block();

        CasdoorAdminClient casdoor = mock(CasdoorAdminClient.class);
        when(casdoor.organization()).thenReturn("hugmesh");
        when(casdoor.addUserToRole(eq(AccessSuspension.ROLE_MASTODON), eq("hugmesh/dave")))
                .thenReturn(Mono.empty());

        SuspensionExpiryAction expiry =
                new SuspensionExpiryAction(casdoor, stubbedHomeserver, repo, leader, noopGateway, noopFederationClear);
        expiry.runOnce().block();

        // Pre-fix (auth-core <=2.3.3) this would call
        // addUserToRole("hugmesh/casdoor:dave@example.org") — a member id the real
        // Casdoor role never contains — and restore would silently no-op forever.
        verify(casdoor, times(1)).addUserToRole(AccessSuspension.ROLE_MASTODON, "hugmesh/dave");
    }

    @Test
    void expiry_permanentBan_neverAutoRestores() {
        AccessSuspensionRepository repo = repo();
        // Permanent (expires_at NULL, restore_role=false) — excluded from dueForRestore.
        repo.insertActive("hugmesh/jack", "jack",
                AccessSuspension.ROLE_MATRIX, null, false, "permanent", "admin", "default").block();

        CasdoorAdminClient casdoor = mock(CasdoorAdminClient.class);
        SuspensionExpiryAction expiry =
                new SuspensionExpiryAction(casdoor, stubbedHomeserver, repo, leader, noopGateway, noopFederationClear);
        expiry.runOnce().block();

        // Still active, never re-added.
        verify(casdoor, never()).addUserToRole(
                org.mockito.ArgumentMatchers.anyString(), org.mockito.ArgumentMatchers.anyString());
        org.assertj.core.api.Assertions.assertThat(
                repo.findActive("hugmesh/jack", AccessSuspension.ROLE_MATRIX).block()).isNotNull();
    }
}
