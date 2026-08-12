package net.hugmesh.adminbff.domainlock;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.r2dbc.core.DatabaseClient;
import org.springframework.test.context.ActiveProfiles;
import reactor.core.publisher.Mono;
import net.hugmesh.authcore.casdoor.CasdoorAdminClient;
import net.hugmesh.adminbff.homeserver.HomeserverAdminClient;
import net.hugmesh.adminbff.lease.AlwaysLeader;
import net.hugmesh.adminbff.lease.LeaderElection;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import net.hugmesh.adminbff.support.AdminBffPostgresTestSupport;

/**
 * The single-writer reconcile behaviour of the domain_lock loop, over a REAL H2
 * repository + a mocked {@link CasdoorAdminClient} + the gated
 * {@link HomeserverAdminClient} stub-seam (domainLockEnabled=false → STUBBED) +
 * AlwaysLeader. Mirrors {@code AccessSyncActionTest}, but ADD-active: an active row =
 * "ADD/KEEP the *_DOMAINLOCKED marker", not "drop the role".
 *
 * <p>Methods call {@code runOnce()} directly — outside the Spring AOP proxy the
 * {@code @CircuitBreaker} annotation is a no-op, so the reconcile body runs straight.
 */
@SpringBootTest(classes = DomainLockSyncActionTest.Boot.class)
@ActiveProfiles("test")
class DomainLockSyncActionTest extends AdminBffPostgresTestSupport {

    @org.springframework.boot.SpringBootConfiguration
    @org.springframework.boot.autoconfigure.EnableAutoConfiguration
    static class Boot { }

    @Autowired DatabaseClient db;

    // domainLockEnabled=false → all force-local seams STUBBED (propagation stays pending)
    private final HomeserverAdminClient stubbedHomeserver =
            new HomeserverAdminClient(null, null, false, false);
    private final LeaderElection leader = new AlwaysLeader();

    // The H2 store is shared across methods in this class (one DatabaseClient per
    // Spring context), so clear domain_lock before each test for full isolation —
    // otherwise a leftover active row from a prior test would feed the reconcile diff.
    @org.junit.jupiter.api.BeforeEach
    void clearTable() {
        db.sql("DELETE FROM domain_lock").fetch().rowsUpdated().block();
    }

    private DomainLockRepository repo() {
        return new DomainLockRepository(net.hugmesh.adminbff.testutil.R2dbcRepos.of(db, net.hugmesh.adminbff.domainlock.DomainLockRowRepository.class));
    }

    @Test
    void activeLock_addsMarker_idempotentSelfHeal_andSetsPropagationPending() {
        DomainLockRepository repo = repo();
        // Desired state: alice is domain-locked on Mastodon.
        repo.insertActive("hugmesh/alice", "alice",
                DomainLock.ROLE_MASTODON_DOMAINLOCKED, "spam", "admin", "default").block();

        CasdoorAdminClient casdoor = mock(CasdoorAdminClient.class);
        when(casdoor.organization()).thenReturn("hugmesh");
        // A concurrent clobber DROPPED the marker; only bob legitimately still carries it
        // but bob is NOT in the active set, so bob is reversed (drop). alice's marker is
        // re-added.
        when(casdoor.getRoleMembers(DomainLock.ROLE_MASTODON_DOMAINLOCKED))
                .thenReturn(Mono.just(List.of("hugmesh/bob")));
        when(casdoor.addUserToRole(eq(DomainLock.ROLE_MASTODON_DOMAINLOCKED), eq("hugmesh/alice")))
                .thenReturn(Mono.empty());
        when(casdoor.removeUserFromRole(eq(DomainLock.ROLE_MASTODON_DOMAINLOCKED), eq("hugmesh/bob")))
                .thenReturn(Mono.empty());

        MastodonDomainLockSyncAction action =
                new MastodonDomainLockSyncAction(casdoor, stubbedHomeserver, repo, leader);
        action.runOnce().block();

        // The loop is the single writer: it (re)ADDS the marker for the active-locked
        // user (self-heal) and DROPS it for a member NOT in the active set (reverse).
        verify(casdoor, times(1)).addUserToRole(DomainLock.ROLE_MASTODON_DOMAINLOCKED, "hugmesh/alice");
        verify(casdoor, times(1)).removeUserFromRole(DomainLock.ROLE_MASTODON_DOMAINLOCKED, "hugmesh/bob");

        // propagation_state stays 'pending' (force-local seam stubbed) so a later tick
        // re-applies once the MRF/egress are real.
        DomainLock after = repo.findActive("hugmesh/alice", DomainLock.ROLE_MASTODON_DOMAINLOCKED).block();
        assertThat(after).isNotNull();
        assertThat(after.propagationState()).isEqualTo(DomainLock.PROP_PENDING);
    }

    @Test
    void unlock_reverses_loopDropsMarkerForNonActiveMember() {
        DomainLockRepository repo = repo();
        // gina WAS locked then unlocked (CAS active->removed) — no active row remains,
        // but Casdoor still carries the marker (clobber / pre-tick). The loop reverses it.
        DomainLock l = repo.insertActive("hugmesh/gina", "gina",
                DomainLock.ROLE_MATRIX_DOMAINLOCKED, null, "admin", "default").block();
        repo.markRemoved(l.id()).block();

        CasdoorAdminClient casdoor = mock(CasdoorAdminClient.class);
        when(casdoor.organization()).thenReturn("hugmesh");
        when(casdoor.getRoleMembers(DomainLock.ROLE_MATRIX_DOMAINLOCKED))
                .thenReturn(Mono.just(List.of("hugmesh/gina")));
        when(casdoor.removeUserFromRole(eq(DomainLock.ROLE_MATRIX_DOMAINLOCKED), eq("hugmesh/gina")))
                .thenReturn(Mono.empty());

        MatrixDomainLockSyncAction action =
                new MatrixDomainLockSyncAction(casdoor, stubbedHomeserver, repo, leader);
        action.runOnce().block();

        // No active lock → the marker is DROPPED and never re-added (reversal).
        verify(casdoor, times(1)).removeUserFromRole(DomainLock.ROLE_MATRIX_DOMAINLOCKED, "hugmesh/gina");
        verify(casdoor, never()).addUserToRole(
                org.mockito.ArgumentMatchers.anyString(), org.mockito.ArgumentMatchers.anyString());
    }

    @Test
    void reconcile_withoutCasdoorClient_doesNotFail_stubSeamOnly() {
        DomainLockRepository repo = repo();
        repo.insertActive("hugmesh/hank", "hank",
                DomainLock.ROLE_MASTODON_DOMAINLOCKED, null, "admin", "default").block();
        // casdoor=null (casdoor.admin.enabled=false) — the loop still runs, only the
        // homeserver stub-seam executes, and it never throws.
        MastodonDomainLockSyncAction action =
                new MastodonDomainLockSyncAction(null, stubbedHomeserver, repo, leader);
        action.runOnce().block(); // completes without error
    }

    @Test
    void notLeader_skipsTheTick_neverWritesCasdoor() {
        DomainLockRepository repo = repo();
        repo.insertActive("hugmesh/ivy", "ivy",
                DomainLock.ROLE_MATRIX_DOMAINLOCKED, null, "admin", "default").block();

        CasdoorAdminClient casdoor = mock(CasdoorAdminClient.class);
        LeaderElection notLeader = new LeaderElection() {
            @Override public boolean isLeader() { return false; }
            @Override public String label() { return "test-not-leader"; }
        };
        MatrixDomainLockSyncAction action =
                new MatrixDomainLockSyncAction(casdoor, stubbedHomeserver, repo, notLeader);
        action.runOnce().block();

        // A non-leader replica never reads or writes Casdoor (single-writer invariant).
        verify(casdoor, never()).getRoleMembers(org.mockito.ArgumentMatchers.anyString());
        verify(casdoor, never()).addUserToRole(
                org.mockito.ArgumentMatchers.anyString(), org.mockito.ArgumentMatchers.anyString());
        verify(casdoor, never()).removeUserFromRole(
                org.mockito.ArgumentMatchers.anyString(), org.mockito.ArgumentMatchers.anyString());
    }
}
