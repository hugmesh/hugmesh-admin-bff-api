package net.hugmesh.adminbff.backingservices;

import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;
import net.hugmesh.adminbff.lease.LeaderElection;

import java.time.Instant;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

/**
 * The Lease-gated SINGLE-WRITER reconcile loop SKELETON for the managed backing-services axis —
 * clones the {@link net.hugmesh.adminbff.optionalservices.OptionalServiceReconciler}
 * contract (the {@code @Scheduled} tick, the {@link LeaderElection} gate, {@code runOnce}, the
 * best-effort error-swallow so a tick failure retries next tick).
 *
 * <h3>v1 = LOGS ONLY (the live flip lever is DEFERRED)</h3>
 * The v1 reconciler reads the CURRENT recorded desired mode per backing service and hands each to
 * the {@link BackingServiceEffector} — whose v1 default ({@link NoopBackingServiceEffector}) does
 * NOTHING but log. NO cluster is dialed and NO consumer endpoint is re-pointed. The real
 * managed-mode flip (prune the in-mesh workload Application + manifests, keep the ESO Secret names
 * sourcing operator-supplied creds, re-point BOTH the R2DBC and Liquibase URLs for a DB) is
 * deliberately deferred to a follow-on generator/effector leg — managed swaps carry real parity
 * blockers (TLS/truststore deltas, out-of-band role-split SQL, Citus incompatibility, and the
 * tier-3 services with no clean managed analog), so v1 records intent + emits honest docs, never
 * pretends to converge production datastores.
 *
 * <h3>SHIPS DARK / fully offline</h3>
 * Gated by {@code app.backing-services.reconcile.enabled} (DEFAULT false): the scheduled tick
 * returns early, so NOTHING runs at defaults. When enabled, it still only calls the (Noop)
 * effector unless a real effector is later wired. The {@link LeaderElection} guard is the SHARED
 * {@code app.access-suspension.lease} (single-replica / dev / test fall back to AlwaysLeader), so
 * at most one replica reconciles a tick.
 */
@Service
@SuppressFBWarnings(value = "EI_EXPOSE_REP2",
        justification = "Spring constructor injection: the container owns this singleton collaborator and it is never mutated by this class after construction; a defensive copy of a bean is meaningless (not caller-owned mutable data).")
public class BackingServiceModeReconciler {

    private static final Logger log = LoggerFactory.getLogger(BackingServiceModeReconciler.class);

    private final boolean enabled;
    private final BackingServiceModeRepository modes;
    private final BackingServiceEffector effector;
    private final LeaderElection leader;

    private final AtomicReference<Instant> lastSuccessAt = new AtomicReference<>(Instant.EPOCH);

    public BackingServiceModeReconciler(
            @Value("${app.backing-services.reconcile.enabled:false}") boolean enabled,
            BackingServiceModeRepository modes,
            BackingServiceEffector effector,
            LeaderElection leader) {
        this.enabled = enabled;
        this.modes = modes;
        this.effector = effector;
        this.leader = leader;
    }

    public Instant lastSuccessAt() {
        return lastSuccessAt.get();
    }

    @Scheduled(
            fixedDelayString = "${app.backing-services.reconcile.interval-ms:30000}",
            initialDelayString = "${app.backing-services.reconcile.initial-delay-ms:24000}")
    public void runTick() {
        runOnce()
                .doOnSuccess(v -> lastSuccessAt.set(Instant.now()))
                .onErrorResume(e -> Mono.empty())
                .subscribe();
    }

    /**
     * One reconcile pass. Skips entirely when DARK (the reconcile flag is off) or when not the
     * leader (single-writer). Errors are swallowed (retry next tick) so the scheduled loop never
     * dies. Reads the current desired mode per service and hands each to the (v1: Noop) effector.
     */
    public Mono<Void> runOnce() {
        if (!enabled) {
            log.debug("[backing-services-reconciler] dark (app.backing-services.reconcile.enabled"
                    + "=false) — skipping tick");
            return Mono.empty();
        }
        if (!leader.isLeader()) {
            log.debug("[backing-services-reconciler] not leader ({}) — skipping tick", leader.label());
            return Mono.empty();
        }
        return modes.currentModes()
                .flatMap(this::reconcileDesired)
                .onErrorResume(e -> {
                    log.warn("[backing-services-reconciler] tick failed (will retry next tick): {}",
                            e.toString());
                    return Mono.empty();
                });
    }

    /**
     * v1 reconcile: for each service with a recorded desired mode, hand it to the effector (Noop
     * logs-only in v1). The effector's blocking work (when a real one is wired) runs on
     * {@code boundedElastic}, the reactive boundary the Velero/optional-services effectors use.
     */
    private Mono<Void> reconcileDesired(Map<String, BackingServiceMode> desired) {
        return reactor.core.publisher.Flux.fromIterable(desired.values())
                .concatMap(effector::applyMode)
                .then()
                .subscribeOn(Schedulers.boundedElastic())
                .doOnSuccess(v -> {
                    if (effector.isReal()) {
                        log.info("[backing-services-reconciler] reconciled {} recorded mode(s)",
                                desired.size());
                    }
                });
    }
}
