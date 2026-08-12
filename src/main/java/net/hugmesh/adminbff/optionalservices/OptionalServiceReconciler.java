package net.hugmesh.adminbff.optionalservices;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;
import net.hugmesh.adminbff.lease.LeaderElection;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

/**
 * The Lease-gated SINGLE-WRITER reconcile loop that turns the {@code OptionalService} CRs
 * (the runtime desired-state) into the two live write targets the build renders at build
 * time — {@code apps/13a-optional-services.yaml}'s element {@code installed} flags and the
 * {@code installed-services} ConfigMap booleans — so a live add/remove flips ONE list
 * instead of editing baked files the running ArgoCD never re-reads. Clones the
 * {@link net.hugmesh.adminbff.storage.NodeStorageReconciler} contract EXACTLY (the
 * {@code @Scheduled} tick, the {@link LeaderElection} gate, {@code runOnce}, the
 * single-writer render, best-effort error-swallow so a tick failure retries next tick).
 *
 * <p>One reconcile pass:
 * <ol>
 *   <li><b>Read.</b> {@link OptionalServiceClient#listDesired()} — every OptionalService
 *       CR (Noop => empty => nothing to do; the feature SHIPS DARK).</li>
 *   <li><b>Resolve desired.</b> Build the desired map keyed by the registry's closed slug
 *       set (a known slug with no CR defaults to {@code false} = not installed; an unknown
 *       slug is logged + ignored). Both write targets are pure functions of this map.</li>
 *   <li><b>Write.</b> The single-writer {@link OptionalServiceApplicationSetPatcher} flips
 *       the 13a elements; the {@link InstalledServicesConfigMapWriter} mirrors the greying
 *       booleans (Noop by default => inert; fabric8 when enabled).</li>
 *   <li><b>Status.</b> Each CR's {@code /status} (phase / installed / observedGeneration /
 *       conditions) is updated so {@code kubectl get optsvc} reflects the effective state.</li>
 * </ol>
 *
 * <p>SHIPS DARK / fully offline-testable: with the Noop client + Noop writers in force the
 * read is empty and NOTHING is written, preserving today's state; with fake seams the whole
 * contract (desired-map derivation, single write, dark-gate, idempotency, status) is
 * exercised without a cluster (see {@code OptionalServiceReconcilerTest}).
 */
@Service
public class OptionalServiceReconciler {

    private static final Logger log = LoggerFactory.getLogger(OptionalServiceReconciler.class);

    private final OptionalServiceClient client;
    private final OptionalServiceApplicationSetPatcher appSetPatcher;
    private final InstalledServicesConfigMapWriter installedWriter;
    private final OptionalServiceRegistry registry;
    private final LeaderElection leader;

    private final AtomicReference<Instant> lastSuccessAt = new AtomicReference<>(Instant.EPOCH);

    public OptionalServiceReconciler(OptionalServiceClient client,
                                     OptionalServiceApplicationSetPatcher appSetPatcher,
                                     InstalledServicesConfigMapWriter installedWriter,
                                     OptionalServiceRegistry registry,
                                     LeaderElection leader) {
        this.client = client;
        this.appSetPatcher = appSetPatcher;
        this.installedWriter = installedWriter;
        this.registry = registry;
        this.leader = leader;
    }

    public Instant lastSuccessAt() {
        return lastSuccessAt.get();
    }

    @Scheduled(
            fixedDelayString = "${app.optional-services.reconcile.interval-ms:30000}",
            initialDelayString = "${app.optional-services.reconcile.initial-delay-ms:22000}")
    public void runTick() {
        runOnce()
                .doOnSuccess(v -> lastSuccessAt.set(Instant.now()))
                .onErrorResume(e -> Mono.empty())
                .subscribe();
    }

    /**
     * One reconcile pass. Skips entirely when not the leader (single-writer). Errors are
     * swallowed (retry next tick) so the scheduled loop never dies. The blocking fabric8
     * seams run on {@code boundedElastic} (the reactive boundary, as in the Velero effector).
     */
    public Mono<Void> runOnce() {
        if (!leader.isLeader()) {
            log.debug("[optional-services-reconciler] not leader ({}) — skipping tick", leader.label());
            return Mono.empty();
        }
        return Mono.<Void>fromRunnable(this::reconcileBlocking)
                .subscribeOn(Schedulers.boundedElastic())
                .onErrorResume(e -> {
                    log.warn("[optional-services-reconciler] tick failed (will retry next tick): {}",
                            e.toString());
                    return Mono.empty();
                });
    }

    private void reconcileBlocking() {
        List<OptionalServiceCr> crs = client.listDesired();

        // Desired map over the CLOSED registry slug set: a known slug with no CR is false
        // (not installed); an unknown slug on a CR is logged + ignored (never actuated).
        Map<String, Boolean> desired = new LinkedHashMap<>();
        for (String slug : registry.slugs()) {
            desired.put(slug, Boolean.FALSE);
        }
        for (OptionalServiceCr cr : crs) {
            if (registry.isKnown(cr.slug())) {
                desired.put(cr.slug(), cr.enabled());
            } else {
                log.warn("[optional-services-reconciler] OptionalService '{}' has unknown slug '{}' — ignoring",
                        cr.name(), cr.slug());
            }
        }

        boolean appOk = appSetPatcher.apply(desired);
        boolean cmOk = installedWriter.mirror(desired);
        boolean bothOk = appOk && cmOk;

        if (appSetPatcher.isReal() || installedWriter.isReal()) {
            log.info("[optional-services-reconciler] reconciled {} desired slug(s): appSet={} configMap={}",
                    desired.size(), appOk, cmOk);
        }

        Instant now = Instant.now();
        for (OptionalServiceCr cr : crs) {
            if (!registry.isKnown(cr.slug())) {
                continue;
            }
            client.updateStatus(cr, computeStatus(cr, desired, appOk, cmOk, bothOk, now));
        }
    }

    /**
     * Compute one CR's status. {@code installed} is reported {@code true} ONLY when the
     * ApplicationSet write succeeded AND the CR wants it on (so a failed write never claims
     * an install); phase reflects the effective outcome; the three conditions record which
     * write targets landed this tick.
     */
    private OptionalServiceStatus computeStatus(OptionalServiceCr cr, Map<String, Boolean> desired,
                                                boolean appOk, boolean cmOk, boolean bothOk, Instant now) {
        boolean want = Boolean.TRUE.equals(desired.get(cr.slug()));
        boolean installed = appOk && want;
        String phase = !bothOk
                ? OptionalServiceStatus.PHASE_DEGRADED
                : (want ? OptionalServiceStatus.PHASE_ENABLED : OptionalServiceStatus.PHASE_DISABLED);

        List<OptionalServiceStatus.Condition> conditions = List.of(
                condition(OptionalServiceStatus.Condition.TYPE_RECONCILED, bothOk,
                        bothOk ? "Reconciled" : "ReconcileError",
                        bothOk ? "desired state applied to both targets"
                               : "one or more write targets failed (retry next tick)",
                        cr.generation(), now),
                condition(OptionalServiceStatus.Condition.TYPE_APPLICATIONSET_PATCHED, appOk,
                        appOk ? "Patched" : "PatchFailed",
                        appOk ? "13a element installed flag written"
                              : "ApplicationSet element write failed",
                        cr.generation(), now),
                condition(OptionalServiceStatus.Condition.TYPE_CONFIGMAP_MIRRORED, cmOk,
                        cmOk ? "Mirrored" : "MirrorFailed",
                        cmOk ? "installed-services boolean mirrored"
                             : "installed-services ConfigMap mirror failed",
                        cr.generation(), now));

        return new OptionalServiceStatus(cr.generation(), installed, phase,
                registry.applicationName(cr.slug()), now, conditions);
    }

    private static OptionalServiceStatus.Condition condition(String type, boolean ok, String reason,
                                                             String message, long generation, Instant now) {
        return new OptionalServiceStatus.Condition(type, ok ? "True" : "False", reason, message, generation, now);
    }
}
