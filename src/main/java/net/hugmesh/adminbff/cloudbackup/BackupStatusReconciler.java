package net.hugmesh.adminbff.cloudbackup;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;
import reactor.core.publisher.Mono;
import net.hugmesh.adminbff.lease.LeaderElection;

import java.time.Instant;
import java.util.concurrent.atomic.AtomicReference;

/**
 * The CATALOG-WRITE STATUS RECONCILER — closes the status-sweep loop the effector leg (#76) +
 * generator Velero leg (#120) flagged as owed: the effector applies a Velero {@code Backup}/
 * {@code Restore} CR and marks the {@code backup_set} {@code running}, but nothing flips the row
 * terminal once Velero finishes. This scheduled sweep periodically lists the BFF-managed Velero CRs
 * (via the read-only {@link VeleroStatusReader} seam), filters to those in a TERMINAL phase, maps
 * each back to its {@code backup_set} row by the reliable id the effector stamped, and drives the
 * row {@code running -> complete/failed} through the EXISTING sole-writer
 * {@code BackupSetRepository.markStatus}.
 *
 * <p>Clones {@code GameInstanceReconciler} / {@code SuspensionExpiryAction} EXACTLY: the
 * {@code @Scheduled} tick, the {@link LeaderElection} single-writer gate, {@code runOnce}, the
 * per-row idempotent transition, and best-effort error-swallow so a tick failure retries next tick
 * (the loop never dies).
 *
 * <h3>CR → set mapping (the reliable identifier)</h3>
 * {@link VeleroCr#setId()} returns the effector-stamped id — the {@code hugmesh.systems/
 * backup-set-id} annotation (the RAW set id) when present, else the same-named label
 * ({@code slug(id)}, which is lossless for the UUID id schema). That single key resolves the row via
 * {@code BackupSetRepository.findById}. A CR with NEITHER (unmappable), or whose id matches no row,
 * is skipped (logged, no crash) — the sweep never fails on a stray CR.
 *
 * <h3>Idempotency (reconciling twice is a no-op)</h3>
 * The RECONCILER guards the transition at the APPLICATION level, not the repository: a row is
 * written ONLY when its pre-read status is {@code pending}/{@code running} AND the CR is terminal.
 * An already-terminal row ({@code complete}/{@code failed}) is skipped BEFORE any write
 * ({@code if (isTerminal(set.status())) skip}), so a second tick — or a second replica —
 * re-reading the same terminal CR does nothing. This pre-read skip is a read-then-write (a TOCTOU),
 * but it is VALUE-idempotent: the same Velero CR always maps to the same deterministic terminal
 * status, so even a racing double-write would write the identical value. {@code markStatus} ITSELF
 * is an UNCONDITIONAL, idempotent {@code UPDATE ... WHERE id = :id} — it carries NO status predicate
 * and does NOT itself enforce a legal transition (it would happily overwrite any status); the legal
 * transition is enforced here, by the pre-read {@code isTerminal} skip. It remains the sole writer
 * of the row's TERMINAL status (the effector only sets {@code running}).
 *
 * <h3>Concurrency (multiple replicas)</h3>
 * Gated by the SAME {@link LeaderElection} bean the suspension + games loops use ({@code AlwaysLeader}
 * for a single replica / dev / test / CI; the k8s {@code Lease} when
 * {@code app.access-suspension.lease.enabled=true}), so at most one replica sweeps at a time.
 * Even WITHOUT the Lease the sweep is safe: the reconciler's pre-read {@code isTerminal} skip plus
 * the value-idempotent UPDATE (the same CR always yields the same deterministic terminal status)
 * make a double-sweep a no-op.
 *
 * <h3>No secrets / no cluster mutation</h3>
 * The sweep READS CR status only (never applies/deletes a CR) and writes ONLY the catalog row. It
 * handles no credentials. The whole reconciler is gated off {@code app.backups.effector.enabled}
 * (see {@link BackupStatusReconcilerConfig}); with the flag off (the default) this bean is ABSENT
 * and nothing lists CRs or touches a cluster.
 */
public class BackupStatusReconciler {

    private static final Logger log = LoggerFactory.getLogger(BackupStatusReconciler.class);

    private final VeleroStatusReader reader;
    private final BackupSetRepository sets;
    private final LeaderElection leader;

    private final AtomicReference<Instant> lastSuccessAt = new AtomicReference<>(Instant.EPOCH);

    public BackupStatusReconciler(VeleroStatusReader reader, BackupSetRepository sets,
                                  LeaderElection leader) {
        this.reader = reader;
        this.sets = sets;
        this.leader = leader;
    }

    public Instant lastSuccessAt() {
        return lastSuccessAt.get();
    }

    @Scheduled(
            fixedDelayString = "${app.backups.reconcile.interval-ms:30000}",
            initialDelayString = "${app.backups.reconcile.initial-delay-ms:20000}")
    public void runTick() {
        runOnce()
                .doOnSuccess(v -> lastSuccessAt.set(Instant.now()))
                .onErrorResume(e -> Mono.empty())
                .subscribe();
    }

    /**
     * One sweep pass for the SCHEDULED loop: lists managed Velero CRs, keeps the terminal ones, and
     * reconciles each back to its catalog row. Skips entirely when not the leader (single-writer).
     * Errors are SWALLOWED (logged, then a {@code 0} count) so a tick failure simply retries on the
     * next tick and the scheduled loop never dies. Returns the count of rows actually flipped
     * terminal. This is the method the {@code @Scheduled} tick drives — its swallow-and-retry
     * behaviour is deliberate and unchanged.
     */
    public Mono<Long> runOnce() {
        return sweepCore()
                .onErrorResume(e -> {
                    log.warn("[cloud-backup-reconciler] sweep failed (will retry next tick): {}",
                            e.toString());
                    return Mono.just(0L);
                });
    }

    /**
     * One sweep pass for the MANUAL trigger: identical to {@link #runOnce()} EXCEPT it PROPAGATES a
     * cluster-read failure instead of swallowing it, so an operator hitting
     * {@code POST /bff/superadmin/cloud-backups/sweep} can tell "nothing to do" ({@code reconciled:0})
     * apart from "the cluster was unreachable" (error -> non-200). The scheduled loop deliberately
     * keeps swallowing+retrying via {@link #runOnce()}; only the on-demand path surfaces the error.
     */
    public Mono<Long> sweepNow() {
        return sweepCore();
    }

    /**
     * The shared sweep body (no error handling): list managed CRs, keep the terminal ones, reconcile
     * each to its catalog row, sum the rows flipped. Skips entirely when not the leader
     * (single-writer). Both {@link #runOnce()} (swallows errors) and {@link #sweepNow()} (propagates
     * them) build on this so the two paths share ONE sweep implementation and differ only in how a
     * failure surfaces.
     */
    private Mono<Long> sweepCore() {
        if (!leader.isLeader()) {
            log.debug("[cloud-backup-reconciler] not leader ({}) — skipping tick", leader.label());
            return Mono.just(0L);
        }
        return reader.listManagedBackupsAndRestores()
                .filter(VeleroCr::isTerminal)
                .concatMap(this::reconcileOne)
                .reduce(0L, Long::sum)
                .doOnNext(n -> {
                    if (n > 0) {
                        log.info("[cloud-backup-reconciler] sweep flipped {} backup set(s) terminal", n);
                    }
                });
    }

    /**
     * Reconcile ONE terminal CR to its {@code backup_set} row. Resolves the row by the reliable
     * stamped id; skips (logs) when the CR is unmappable or the row is missing or ALREADY terminal.
     * Otherwise flips {@code pending}/{@code running -> complete/failed} via the sole-writer
     * {@code markStatus}. Returns 1 when a row was written, else 0.
     */
    private Mono<Long> reconcileOne(VeleroCr cr) {
        String setId = cr.setId();
        if (setId == null) {
            log.warn("[cloud-backup-reconciler] terminal Velero {} '{}' carries no backup-set id "
                    + "(annotation/label) — UNMAPPABLE, skipping", cr.kind(), cr.name());
            return Mono.just(0L);
        }
        return sets.findById(setId)
                // Skip terminal sets; otherwise flip the status from the Velero CR.
                .flatMap(set -> reconcileBackupSet(set, cr))
                .switchIfEmpty(Mono.fromSupplier(() -> {
                    log.debug("[cloud-backup-reconciler] terminal Velero {} '{}' maps to set id={} "
                            + "but no such row — skipping", cr.kind(), cr.name(), setId);
                    return 0L;
                }));
    }

    /** Skip an already-terminal set; otherwise write the new status from the Velero CR. */
    private Mono<Long> reconcileBackupSet(BackupSet set, VeleroCr cr) {
        if (isTerminal(set.status())) {
            // Already complete/failed — idempotent skip BEFORE any write.
            log.debug("[cloud-backup-reconciler] set id={} already terminal ({}) — "
                    + "skipping CR {} '{}'", set.id(), set.status(), cr.kind(), cr.name());
            return Mono.just(0L);
        }
        String target = cr.catalogStatus();
        return sets.markStatus(set.id(), target, set.sizeBytes())
                .map(rows -> {
                    if (rows != null && rows > 0) {
                        log.info("[cloud-backup-reconciler] set id={} {} -> {} from "
                                        + "Velero {} '{}' (phase={})",
                                set.id(), set.status(), target, cr.kind(), cr.name(), cr.phase());
                        return 1L;
                    }
                    return 0L;
                });
    }

    private static boolean isTerminal(String status) {
        return BackupSet.STATUS_COMPLETE.equals(status) || BackupSet.STATUS_FAILED.equals(status);
    }
}
