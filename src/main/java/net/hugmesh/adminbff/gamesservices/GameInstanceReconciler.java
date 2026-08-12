package net.hugmesh.adminbff.gamesservices;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import net.hugmesh.adminbff.lease.LeaderElection;

import java.time.Instant;
import java.util.concurrent.atomic.AtomicReference;

/**
 * The Lease-gated SINGLE-WRITER reconcile loop for game instances — clones
 * {@link net.hugmesh.adminbff.suspension.SuspensionExpiryAction} EXACTLY (the
 * {@code @Scheduled} tick, the {@link LeaderElection} gate, {@code runOnce}, the CAS-guarded
 * per-row transition, and best-effort error-swallow so a tick failure retries next tick).
 *
 * <p>Two responsibilities per tick (in order):
 * <ol>
 *   <li><b>Expiry.</b> Scan {@code ending_at <= now AND state='active'} and CAS each
 *       {@code active -> terminated} (the SuspensionExpiryAction idiom: one clock, one CAS;
 *       only the writer that wins rows-updated==1 proceeds, so a second replica/tick never
 *       double-terminates). A terminated instance drops out of the next ConfigMap render
 *       (teardown).</li>
 *   <li><b>Render.</b> admin-bff is the SINGLE writer of the per-domain ACTIVE-instance
 *       ConfigMaps the generator's apps/13c ApplicationSet reads. For every domain with
 *       active instances, render the desired set into its ConfigMap and reconcile each
 *       row's {@code propagation_state} forward ({@code applied} on success, {@code failed}
 *       to retry next tick). ArgoCD is apply-only — the Lease + propagation_state are the
 *       SOLE coordination, or instances flap.</li>
 * </ol>
 *
 * <p>Single-writer via {@link LeaderElection} (the SAME bean the suspension loop uses) + the
 * casState CAS. Survives restarts: the scan re-selects every overdue/active row on boot.
 * When the cluster-less {@link NoopInstanceConfigMapWriter} is in force the render is a
 * no-op but the CAS + propagation_state contract still runs (so the loop is fully testable
 * without a live cluster).
 */
@Service
public class GameInstanceReconciler {

    private static final Logger log = LoggerFactory.getLogger(GameInstanceReconciler.class);

    private final GameInstanceRepository repo;
    private final LeaderElection leader;
    private final InstanceConfigMapWriter writer;
    private final NodePortAllocator nodePorts;
    private final GameServerCatalogRepository catalog;
    private final String namespace;

    private final AtomicReference<Instant> lastSuccessAt = new AtomicReference<>(Instant.EPOCH);

    public GameInstanceReconciler(GameInstanceRepository repo,
                                  LeaderElection leader,
                                  InstanceConfigMapWriter writer,
                                  NodePortAllocator nodePorts,
                                  GameServerCatalogRepository catalog,
                                  @org.springframework.beans.factory.annotation.Value(
                                          "${games-services.reconciler.namespace:hugmesh-games-instances}")
                                  String namespace) {
        this.repo = repo;
        this.leader = leader;
        this.writer = writer;
        this.nodePorts = nodePorts;
        this.catalog = catalog;
        this.namespace = namespace;
    }

    public Instant lastSuccessAt() {
        return lastSuccessAt.get();
    }

    @Scheduled(
            fixedDelayString = "${games-services.reconcile.interval-ms:15000}",
            initialDelayString = "${games-services.reconcile.initial-delay-ms:14000}")
    public void runTick() {
        runOnce()
                .doOnSuccess(v -> lastSuccessAt.set(Instant.now()))
                .onErrorResume(e -> Mono.empty())
                .subscribe();
    }

    /** One reconcile pass: expire overdue instances, then render every domain's ConfigMap.
     *  Skips entirely when not the leader (single-writer). Errors are swallowed (retry next
     *  tick) so the scheduled loop never dies. */
    public Mono<Void> runOnce() {
        if (!leader.isLeader()) {
            log.debug("[games-reconciler] not leader ({}) — skipping tick", leader.label());
            return Mono.empty();
        }
        return expireDue()
                .then(renderAllDomains())
                .onErrorResume(e -> {
                    log.warn("[games-reconciler] tick failed (will retry next tick): {}", e.toString());
                    return Mono.empty();
                });
    }

    /** CAS {@code active -> terminated} for every instance past its TTL. */
    private Mono<Void> expireDue() {
        return repo.dueForExpiry(Instant.now())
                .concatMap(this::terminateExpired)
                .then();
    }

    private Mono<Void> terminateExpired(GameInstance i) {
        return repo.casState(i.id(), GameInstance.STATE_TERMINATED, GameInstance.STATE_ACTIVE)
                .flatMap(rows -> {
                    if (rows == null || rows == 0) {
                        // Another tick/replica already moved it — nothing to do.
                        return Mono.empty();
                    }
                    log.info("[games-reconciler] terminating expired instance {}/{}/{} (id={})",
                            i.domain(), i.slug(), i.name(), i.id());
                    return Mono.empty();
                });
    }

    /** Render the per-domain ConfigMap for every domain with active instances and reconcile
     *  each rendered row's propagation_state forward. */
    private Mono<Void> renderAllDomains() {
        return repo.domainsWithActive()
                .concatMap(this::renderDomain)
                .then();
    }

    private Mono<Void> renderDomain(String domain) {
        // 1) Ensure each active instance has its port/console/namespace assigned (the
        //    reconciler is the single Lease-gated writer, so this is race-safe), then
        // 2) re-read + render the freshly-assigned set into the per-domain ConfigMap.
        return repo.activeByDomain(domain)
                .concatMap(this::ensureExposure)
                .then(repo.activeByDomain(domain).collectList())
                .flatMap(instances -> {
                    boolean ok = writer.writeDomainConfigMap(domain, instances);
                    String prop = ok ? GameInstance.PROP_APPLIED : GameInstance.PROP_FAILED;
                    // Forward-reconcile every rendered row's propagation_state (idempotent;
                    // a 'failed' row is retried next tick when the write recovers).
                    return Flux.fromIterable(instances)
                            .concatMap(i -> repo.updatePropagationState(i.id(), prop))
                            .then();
                });
    }

    /**
     * Allocate a NodePort (for catalog servers whose protocol is NOT 'none') + set the HTTP
     * console_path + the games-instances namespace on an active instance that lacks them.
     * Idempotent: the repo writes are CAS-guarded (node_port/namespace IS NULL), so a row
     * that already has them is untouched, and a fully-exposed instance is a no-op. Best-
     * effort: a NodePort-pool-exhausted error is swallowed (the instance simply renders
     * without a port this tick and retries next tick) so one exhaustion never stalls the loop.
     */
    private Mono<Void> ensureExposure(GameInstance i) {
        Mono<Void> ns = (i.namespace() == null)
                ? repo.assignNamespace(i.id(), namespace).then()
                : Mono.empty();
        Mono<Void> port = (i.nodePort() != null)
                ? Mono.empty()
                // Allocate NodePort + console path for the catalog entry that matches this instance.
                : catalog.findBySlug(i.slug()).flatMap(entry -> assignExposure(i, entry)).then();
        return ns.then(port);
    }

    /** Assign NodePort and HTTP console path to the instance based on its catalog entry. */
    private Mono<Void> assignExposure(GameInstance i, GameServerCatalogEntry entry) {
        String consolePath = (entry.consolePort() != null)
                ? "/games/servers/" + i.slug() + "/" + i.name() + "/"
                : null;
        boolean needsNodePort = entry.protocol() != null
                && !GameServerCatalogEntry.PROTOCOL_NONE.equals(entry.protocol());
        if (!needsNodePort) {
            // HTTP-only server: no NodePort, just the console path.
            return consolePath == null ? Mono.empty()
                    : repo.assignPortAndConsole(i.id(), -1, consolePath).then();
        }
        return nodePorts.allocate()
                .flatMap(p -> repo.assignPortAndConsole(i.id(), p, consolePath)
                        .doOnNext(rows -> {
                            if (rows != null && rows > 0) {
                                log.info("[games-nodeport] allocated {} to {}/{}/{} (id={})",
                                        p, i.domain(), i.slug(), i.name(), i.id());
                            }
                        }).then())
                .onErrorResume(NodePortAllocator.NodePortExhaustedException.class, e -> {
                    log.warn("[games-nodeport] could not allocate for {} (id={}): {}",
                            i.name(), i.id(), e.getMessage());
                    return Mono.empty();
                });
    }
}
