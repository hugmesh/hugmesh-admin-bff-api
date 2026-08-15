package net.hugmesh.adminbff.desktop;

import org.junit.jupiter.api.Test;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;
import net.hugmesh.adminbff.lease.LeaderElection;

import java.time.Instant;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * The claim-propagation worker over a MOCKED {@link DesktopSudoGrantRepository} +
 * {@link DesktopSudoClaimSync} (NEVER a real DB or IdP) + a toggleable fake leader — the
 * {@link net.hugmesh.adminbff.cloudbackup.BackupStatusReconcilerTest} shape. Pins the
 * retry-loop contract:
 * <ul>
 *   <li>a {@code pending} row whose push lands -> stamped {@code applied}, counted;</li>
 *   <li>a previously {@code failed} row is IN the sweep set and retried to {@code applied};</li>
 *   <li>a push that fails again -> stamped {@code failed} (count 0) and the NEXT tick
 *       retries it — failure -> retry -> converge;</li>
 *   <li>an unchanged outcome (still pending / still failed) -> NO propagation-state write;</li>
 *   <li>not-leader -> the whole sweep is skipped (single-writer);</li>
 *   <li>a sweep error is SWALLOWED (returns 0) so the scheduled loop never dies.</li>
 * </ul>
 */
class DesktopSudoClaimReconcilerTest {

    private final DesktopSudoGrantRepository repo = mock(DesktopSudoGrantRepository.class);
    private final DesktopSudoClaimSync sync = mock(DesktopSudoClaimSync.class);

    /** A leader gate we can flip (the BackupStatusReconcilerTest FakeLeader idiom). */
    static final class FakeLeader implements LeaderElection {
        boolean leader = true;
        @Override public boolean isLeader() { return leader; }
        @Override public String label() { return "fake(leader=" + leader + ")"; }
    }

    private final FakeLeader leader = new FakeLeader();
    private final DesktopSudoClaimReconciler reconciler =
            new DesktopSudoClaimReconciler(repo, sync, leader);

    private static DesktopSudoGrant owing(String id, String propagationState) {
        return new DesktopSudoGrant(id, "alice", "dev-1", DesktopSudoGrant.STATE_ACTIVE, "root",
                Instant.now(), null, null, "brandx", propagationState, 1L);
    }

    // ── pending -> applied ───────────────────────────────────────────────────────

    @Test
    void pendingRow_pushLands_stampedApplied_counted() {
        DesktopSudoGrant g = owing("g-1", DesktopSudoGrant.PROP_PENDING);
        when(repo.pendingPropagation()).thenReturn(Flux.just(g));
        when(sync.propagate(g)).thenReturn(Mono.just(DesktopSudoGrant.PROP_APPLIED));
        when(repo.updatePropagationState("g-1", DesktopSudoGrant.PROP_APPLIED))
                .thenReturn(Mono.just(1L));

        StepVerifier.create(reconciler.runOnce()).expectNext(1L).verifyComplete();

        verify(repo).updatePropagationState("g-1", DesktopSudoGrant.PROP_APPLIED);
    }

    @Test
    void failedRow_isInSweepSet_retriedToApplied() {
        // A row a previous push left 'failed' MUST be retried — the sweep set is
        // pending OR failed (pendingPropagation), not pending alone.
        DesktopSudoGrant g = owing("g-1", DesktopSudoGrant.PROP_FAILED);
        when(repo.pendingPropagation()).thenReturn(Flux.just(g));
        when(sync.propagate(g)).thenReturn(Mono.just(DesktopSudoGrant.PROP_APPLIED));
        when(repo.updatePropagationState("g-1", DesktopSudoGrant.PROP_APPLIED))
                .thenReturn(Mono.just(1L));

        StepVerifier.create(reconciler.runOnce()).expectNext(1L).verifyComplete();

        verify(repo).updatePropagationState("g-1", DesktopSudoGrant.PROP_APPLIED);
    }

    // ── failure -> retry -> converge ─────────────────────────────────────────────

    @Test
    void pushFailsAgain_stampedFailed_nextTickRetriesToApplied() {
        DesktopSudoGrant pending = owing("g-1", DesktopSudoGrant.PROP_PENDING);
        DesktopSudoGrant failed = owing("g-1", DesktopSudoGrant.PROP_FAILED);
        when(repo.pendingPropagation())
                .thenReturn(Flux.just(pending))   // tick 1 sees the pending row
                .thenReturn(Flux.just(failed));   // tick 2 sees the failed stamp
        when(sync.propagate(pending)).thenReturn(Mono.just(DesktopSudoGrant.PROP_FAILED));
        when(sync.propagate(failed)).thenReturn(Mono.just(DesktopSudoGrant.PROP_APPLIED));
        when(repo.updatePropagationState(anyString(), anyString())).thenReturn(Mono.just(1L));

        // tick 1: the push fails -> row stamped 'failed', nothing counted as propagated.
        StepVerifier.create(reconciler.runOnce()).expectNext(0L).verifyComplete();
        verify(repo).updatePropagationState("g-1", DesktopSudoGrant.PROP_FAILED);

        // tick 2: the SAME row is re-driven and lands -> 'applied', counted.
        StepVerifier.create(reconciler.runOnce()).expectNext(1L).verifyComplete();
        verify(repo).updatePropagationState("g-1", DesktopSudoGrant.PROP_APPLIED);
    }

    @Test
    void unchangedOutcome_noWrite() {
        // The Noop (lever off) — or a dry-run — reports 'pending' for a pending row: the
        // state did not change, so the reconciler must NOT rewrite it.
        DesktopSudoGrant g = owing("g-1", DesktopSudoGrant.PROP_PENDING);
        when(repo.pendingPropagation()).thenReturn(Flux.just(g));
        when(sync.propagate(g)).thenReturn(Mono.just(DesktopSudoGrant.PROP_PENDING));

        StepVerifier.create(reconciler.runOnce()).expectNext(0L).verifyComplete();

        verify(repo, never()).updatePropagationState(anyString(), anyString());
    }

    // ── single-writer + loop survival ────────────────────────────────────────────

    @Test
    void notLeader_skipsEntireSweep() {
        leader.leader = false;

        StepVerifier.create(reconciler.runOnce()).expectNext(0L).verifyComplete();

        verify(repo, never()).pendingPropagation();
    }

    @Test
    void sweepError_isSwallowed_returnsZero_forScheduledRetry() {
        when(repo.pendingPropagation())
                .thenReturn(Flux.error(new IllegalStateException("db unreachable")));

        // The scheduled loop must NEVER die on a tick failure — it logs and returns 0.
        StepVerifier.create(reconciler.runOnce()).expectNext(0L).verifyComplete();

        verify(repo, never()).updatePropagationState(anyString(), anyString());
    }
}
