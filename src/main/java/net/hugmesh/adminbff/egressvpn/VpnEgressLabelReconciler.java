package net.hugmesh.adminbff.egressvpn;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;
import reactor.core.publisher.Mono;
import net.hugmesh.adminbff.lease.LeaderElection;

import java.time.Instant;
import java.util.concurrent.atomic.AtomicReference;

/**
 * The DRIFT SWEEP for the egress-VPN pod-labeling leg — the scheduled convergence loop that
 * re-runs {@link VpnEgressLabeler#reconcile()} on a cadence so label state converges even when
 * no admin mutation fires: a pod REPLACED between mutations starts unlabelled (fail-closed onto
 * the Squid-proxy/default-deny path, never a leak) and is re-labelled within one tick; a stray
 * label left by a deleted workload is swept clean. The on-mutation fast path in
 * {@link EgressVpnService} calls the SAME {@code reconcile()}, so the two paths cannot diverge.
 *
 * <p>Clones {@link net.hugmesh.adminbff.cloudbackup.BackupStatusReconciler} EXACTLY: the
 * {@code @Scheduled} tick, the {@link LeaderElection} single-writer gate, {@code runOnce}, and
 * best-effort error-swallow so a tick failure retries next tick (the loop never dies —
 * {@code reconcile()} itself already swallows cluster errors to a 0 count).
 *
 * <p>Registered ONLY when {@code app.egress-vpn.labeler.enabled=true} (see
 * {@link EgressVpnLabelerConfig}); with the flag off (the DEFAULT) this bean is ABSENT and no
 * {@code @Scheduled} sweep exists, so nothing lists workloads or dials a cluster.
 */
public class VpnEgressLabelReconciler {

    private static final Logger log = LoggerFactory.getLogger(VpnEgressLabelReconciler.class);

    private final VpnEgressLabeler labeler;
    private final LeaderElection leader;

    private final AtomicReference<Instant> lastSuccessAt = new AtomicReference<>(Instant.EPOCH);

    public VpnEgressLabelReconciler(VpnEgressLabeler labeler, LeaderElection leader) {
        this.labeler = labeler;
        this.leader = leader;
    }

    public Instant lastSuccessAt() {
        return lastSuccessAt.get();
    }

    @Scheduled(
            fixedDelayString = "${app.egress-vpn.labeler.interval-ms:30000}",
            initialDelayString = "${app.egress-vpn.labeler.initial-delay-ms:25000}")
    public void runTick() {
        runOnce()
                .doOnSuccess(v -> lastSuccessAt.set(Instant.now()))
                .onErrorResume(e -> Mono.empty())
                .subscribe();
    }

    /**
     * One sweep pass: converge the label state via the shared {@link VpnEgressLabeler}. Skips
     * entirely when not the leader (single-writer). Errors are swallowed INSIDE
     * {@code reconcile()} (logged, then a {@code 0} count), so a tick failure simply retries on
     * the next tick and the scheduled loop never dies.
     */
    public Mono<Long> runOnce() {
        if (!leader.isLeader()) {
            log.debug("[egress-vpn-labeler] not leader ({}) — skipping tick", leader.label());
            return Mono.just(0L);
        }
        return labeler.reconcile();
    }
}
