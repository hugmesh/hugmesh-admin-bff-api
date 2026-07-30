package systems.hugmesh.adminbff.storage;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import systems.hugmesh.adminbff.device.DeviceRegistryRepository;
import systems.hugmesh.adminbff.lease.LeaderElection;

import java.time.Instant;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;

/**
 * The Lease-gated SINGLE-WRITER reconcile loop that renders the ACTIVE
 * {@code storage_service_assignment} rows into the {@code node-storage-assignments} ConfigMap
 * the generator's {@code apps/13b-node-storage.yaml} ApplicationSet consumes (one placement
 * Application — nodeAffinity + node-pinned PVC — per element). This is the software bridge that
 * makes the as-merged INERT 13b list ({@code elements: []}) match the BFF's live assignment
 * state. Clones the games {@link systems.hugmesh.adminbff.gamesservices.GameInstanceReconciler}
 * EXACTLY (the {@code @Scheduled} tick, the {@link LeaderElection} gate, {@code runOnce}, the
 * single-writer render, the {@code propagation_state} forward-reconcile, and best-effort
 * error-swallow so a tick failure retries next tick).
 *
 * <p>One reconcile pass:
 * <ol>
 *   <li><b>Read.</b> {@link ServiceAssignmentRepository#listActiveAll()} — every brand's ACTIVE
 *       rows (the 13b list-generator's full working set; 13b carries ONE global list).</li>
 *   <li><b>Resolve + render.</b> For each row, resolve its pool ({@code poolId -> poolPath}) and
 *       the pool's node ({@code pool.deviceId -> Device.hostname}) into the
 *       {@link StorageAssignmentElement} 13b shape, stamping the configured service namespace,
 *       then write the whole desired set into the ConfigMap via the
 *       {@link NodeStorageConfigMapWriter} (Noop by default => inert; fabric8 when enabled).</li>
 *   <li><b>Forward-reconcile.</b> On a successful apply, CAS each rendered row's
 *       {@code propagation_state -> applied}; on a failed apply, {@code -> failed} so it is
 *       retried next tick. ArgoCD is apply-only — the Lease + propagation_state are the SOLE
 *       coordination, or placements flap.</li>
 * </ol>
 *
 * <p>SHIPS SAFE: with NO active assignments the render is an EMPTY element list — the ConfigMap
 * is written empty (or, under the Noop default, not written at all), preserving today's inert
 * state (13b generates zero placements). The per-node {@code nodePathMap} node-agent leg
 * (fleet-gated, generator PR6) is OUT OF SCOPE — this reconciler only renders the desired-set
 * ConfigMap; the node-agent binds the PV on the pool's node separately.
 *
 * <p>Single-writer via {@link LeaderElection} (the SAME bean the games + suspension loops use).
 * Survives restarts: the scan re-selects every active row on boot. When the cluster-less
 * {@link NoopNodeStorageConfigMapWriter} is in force the render is a no-op but the read + the
 * propagation_state forward-reconcile still run, so the loop is fully testable without a live
 * cluster.
 */
@Service
public class NodeStorageReconciler {

    private static final Logger log = LoggerFactory.getLogger(NodeStorageReconciler.class);

    private final ServiceAssignmentRepository assignments;
    private final StoragePoolRepository pools;
    private final DeviceRegistryRepository devices;
    private final LeaderElection leader;
    private final NodeStorageConfigMapWriter writer;
    private final String serviceNamespace;

    private final AtomicReference<Instant> lastSuccessAt = new AtomicReference<>(Instant.EPOCH);

    public NodeStorageReconciler(ServiceAssignmentRepository assignments,
                                 StoragePoolRepository pools,
                                 DeviceRegistryRepository devices,
                                 LeaderElection leader,
                                 NodeStorageConfigMapWriter writer,
                                 @Value("${node-storage.reconciler.service-namespace:hugmesh-backend}")
                                 String serviceNamespace) {
        this.assignments = assignments;
        this.pools = pools;
        this.devices = devices;
        this.leader = leader;
        this.writer = writer;
        this.serviceNamespace = (serviceNamespace == null || serviceNamespace.isBlank())
                ? "hugmesh-backend" : serviceNamespace;
    }

    public Instant lastSuccessAt() {
        return lastSuccessAt.get();
    }

    @Scheduled(
            fixedDelayString = "${node-storage.reconcile.interval-ms:15000}",
            initialDelayString = "${node-storage.reconcile.initial-delay-ms:16000}")
    public void runTick() {
        runOnce()
                .doOnSuccess(v -> lastSuccessAt.set(Instant.now()))
                .onErrorResume(e -> Mono.empty())
                .subscribe();
    }

    /**
     * One reconcile pass: render every active assignment into the ConfigMap and forward-reconcile
     * each rendered row's propagation_state. Skips entirely when not the leader (single-writer).
     * Errors are swallowed (retry next tick) so the scheduled loop never dies.
     */
    public Mono<Void> runOnce() {
        if (!leader.isLeader()) {
            log.debug("[node-storage-reconciler] not leader ({}) — skipping tick", leader.label());
            return Mono.empty();
        }
        return assignments.listActiveAll()
                .concatMap(this::toElement)
                .collectList()
                .flatMap(this::renderAndReconcile)
                .onErrorResume(e -> {
                    log.warn("[node-storage-reconciler] tick failed (will retry next tick): {}",
                            e.toString());
                    return Mono.empty();
                });
    }

    /** A rendered element paired with its source assignment id (for the propagation CAS). */
    private record Rendered(String assignmentId, StorageAssignmentElement element) {}

    /**
     * Resolve one active assignment into its 13b element: pool ({@code poolPath}) then the
     * pool's node ({@code pool.deviceId -> Device.hostname} for {@code nodeName}). A pool or
     * device that cannot be resolved still yields an element with empty node/path (so the row is
     * never silently dropped from the desired set); the placement Application simply lacks a
     * pin until residency resolves.
     */
    private Mono<Rendered> toElement(ServiceAssignment a) {
        return pools.findById(a.poolId())
                .flatMap(pool -> resolveNodeName(pool.deviceId())
                        .map(node -> render(a, pool, node)))
                .switchIfEmpty(Mono.fromSupplier(() -> render(a, null, "")));
    }

    private Rendered render(ServiceAssignment a, StoragePool pool, String nodeName) {
        return new Rendered(a.id(),
                StorageAssignmentElement.of(a, pool, nodeName, serviceNamespace));
    }

    /** {@code deviceId -> hostname}; empty (not error) when the device is absent/unset. */
    private Mono<String> resolveNodeName(String deviceId) {
        if (deviceId == null || deviceId.isBlank()) {
            return Mono.just("");
        }
        return devices.findById(deviceId)
                .map(d -> d.hostname() == null ? "" : d.hostname())
                .defaultIfEmpty("");
    }

    /**
     * Write the whole desired set into the ConfigMap, then forward-reconcile each rendered row's
     * propagation_state (applied on success, failed to retry next tick). An EMPTY set writes an
     * empty ConfigMap (the inert default) and there is nothing to reconcile.
     */
    private Mono<Void> renderAndReconcile(List<Rendered> rendered) {
        List<StorageAssignmentElement> elements = rendered.stream().map(Rendered::element).toList();
        boolean ok = writer.writeAssignments(elements);
        String prop = ok ? ServiceAssignment.PROP_APPLIED : ServiceAssignment.PROP_FAILED;
        if (writer.isReal()) {
            log.info("[node-storage-reconciler] rendered {} active assignment(s) -> {}",
                    elements.size(), prop);
        }
        return Flux.fromIterable(rendered)
                .concatMap(r -> assignments.updatePropagationState(r.assignmentId(), prop))
                .then();
    }
}
