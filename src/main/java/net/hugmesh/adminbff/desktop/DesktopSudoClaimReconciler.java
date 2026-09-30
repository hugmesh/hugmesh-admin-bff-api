package net.hugmesh.adminbff.desktop;

import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;
import reactor.core.publisher.Mono;
import net.hugmesh.adminbff.lease.LeaderElection;

import java.time.Instant;
import java.util.concurrent.atomic.AtomicReference;

/**
 * The DESKTOP-SUDO CLAIM PROPAGATION WORKER — closes the loop the grant/revoke rows arm:
 * every mutate leaves {@code propagation_state='pending'} (insert + both CAS revokes stamp
 * it), and the inline {@link DesktopSudoClaimSync} push can fail or run dark, so this
 * scheduled sweep re-reads every row still owing propagation ({@code pending} OR a previous
 * {@code failed}) and re-drives it through the SAME sync seam until it lands
 * {@code applied}. A row that fails again is stamped {@code failed} and picked up by the
 * next tick — the retry loop never dies and never forgets a row (the sweep set is the DB,
 * not memory, so it survives restarts).
 *
 * <p>Clones {@link net.hugmesh.adminbff.cloudbackup.BackupStatusReconciler} EXACTLY: the
 * {@code @Scheduled} tick, the {@link LeaderElection} single-writer gate, {@code runOnce}'s
 * swallow-and-retry, and the per-row idempotent transition (a state that did not change is
 * not rewritten). Registered ONLY when {@code app.desktop.sudo.claim-sync.enabled=true}
 * (see {@link DesktopSudoClaimSyncConfig}) — by default the bean is ABSENT and no sweep
 * exists.
 *
 * <h3>Idempotency (sweeping twice is a no-op)</h3>
 * {@link DesktopSudoClaimSync#propagate} is VALUE-idempotent: the desired Casdoor membership
 * is a pure function of the DB rows (active grant → member; no active grant → not a member)
 * and Casdoor's add/remove dedup, so a double sweep — or the inline push racing a tick —
 * converges on the same membership. The {@code propagation_state} write is guarded by a
 * changed-value check, so an already-{@code applied} row is skipped before any write.
 */
@SuppressFBWarnings(value = "EI_EXPOSE_REP2",
        justification = "Spring constructor injection: the container owns this singleton collaborator and it is never mutated by this class after construction; a defensive copy of a bean is meaningless (not caller-owned mutable data).")
public class DesktopSudoClaimReconciler {

    private static final Logger log = LoggerFactory.getLogger(DesktopSudoClaimReconciler.class);

    private final DesktopSudoGrantRepository repo;
    private final DesktopSudoClaimSync claimSync;
    private final LeaderElection leader;

    private final AtomicReference<Instant> lastSuccessAt = new AtomicReference<>(Instant.EPOCH);

    public DesktopSudoClaimReconciler(DesktopSudoGrantRepository repo,
                                      DesktopSudoClaimSync claimSync,
                                      LeaderElection leader) {
        this.repo = repo;
        this.claimSync = claimSync;
        this.leader = leader;
    }

    public Instant lastSuccessAt() {
        return lastSuccessAt.get();
    }

    @Scheduled(
            fixedDelayString = "${app.desktop.sudo.claim-sync.interval-ms:30000}",
            initialDelayString = "${app.desktop.sudo.claim-sync.initial-delay-ms:26000}")
    public void runTick() {
        runOnce()
                .doOnSuccess(v -> lastSuccessAt.set(Instant.now()))
                .onErrorResume(e -> Mono.empty())
                .subscribe();
    }

    /**
     * One sweep pass: re-drive every row still owing propagation through the sync seam.
     * Skips entirely when not the leader (single-writer). Errors are SWALLOWED (logged,
     * then a {@code 0} count) so a tick failure simply retries on the next tick and the
     * scheduled loop never dies. Returns the count of rows that reached {@code applied}.
     */
    public Mono<Long> runOnce() {
        if (!leader.isLeader()) {
            log.debug("[desktop-sudo-claim] not leader ({}) — skipping tick", leader.label());
            return Mono.just(0L);
        }
        return repo.pendingPropagation()
                .concatMap(this::reconcileOne)
                .reduce(0L, Long::sum)
                .doOnNext(n -> {
                    if (n > 0) {
                        log.info("[desktop-sudo-claim] sweep propagated {} grant(s)", n);
                    }
                })
                .onErrorResume(e -> {
                    log.warn("[desktop-sudo-claim] sweep failed (will retry next tick): {}",
                            e.toString());
                    return Mono.just(0L);
                });
    }

    /** Re-drive ONE owed row; stamp the outcome only when it changed. Returns 1 when the row
     *  reached {@code applied}, else 0 (still pending/failed — next tick retries). */
    private Mono<Long> reconcileOne(DesktopSudoGrant grant) {
        return claimSync.propagate(grant)
                .flatMap(state -> {
                    if (state.equals(grant.propagationState())) {
                        return Mono.just(0L);
                    }
                    return repo.updatePropagationState(grant.id(), state)
                            .doOnNext(rows -> log.info(
                                    "[desktop-sudo-claim] grant id={} propagation {} -> {}",
                                    grant.id(), grant.propagationState(), state))
                            .map(rows -> DesktopSudoGrant.PROP_APPLIED.equals(state) ? 1L : 0L);
                });
    }
}
