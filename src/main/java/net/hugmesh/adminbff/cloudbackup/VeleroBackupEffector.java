package net.hugmesh.adminbff.cloudbackup;

import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import io.fabric8.kubernetes.api.model.GenericKubernetesResource;
import io.fabric8.kubernetes.client.KubernetesClient;
import io.fabric8.kubernetes.client.dsl.base.ResourceDefinitionContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

/**
 * The REAL {@link BackupEffector}: translates a {@link BackupSet} (its scope + destination +
 * per-service artifacts) into a Velero ({@code velero.io/v1}) {@code Backup} CR on
 * {@link #startBackup}, and a Velero {@code Restore} CR on {@link #startRestore}, applied via
 * the fabric8 {@link KubernetesClient} already on the classpath (the SAME client/style the
 * Workload Console {@code Fabric8WorkloadClient} and the games {@code Fabric8InstanceConfigMapWriter}
 * use). The CR SHAPE is built by the pure {@link VeleroResourceFactory} (unit-tested without a
 * cluster); this class only applies it and drives the catalog statuses.
 *
 * <h3>SHIPS DARK</h3>
 * Wired ONLY when {@code app.backups.effector.enabled=true} (see {@link BackupEffectorConfig}).
 * With the flag OFF (the DEFAULT — every dev/test/CI run and every deployment until the
 * generator/Velero leg provisions the BackupStorageLocation + credentials) the foundation's
 * {@code @ConditionalOnMissingBean NoopBackupEffector} stays the active bean and NOTHING here
 * is constructed, so no cluster is dialed.
 *
 * <h3>Reactive boundary + fail-closed</h3>
 * The blocking fabric8 apply runs on {@code boundedElastic} (the reactive boundary, as in
 * {@code Fabric8WorkloadClient}). The {@link KubernetesClient} is supplied LAZILY by a
 * {@link ClientFactory} (built on first apply, not at boot) so a transient API-server blip
 * never bricks BFF boot — only an actual backup/restore touches the API server. A cluster-side
 * rejection (RBAC/admission/conflict) marks the set {@code failed} and completes the Mono
 * (the catalog records the failure; the request is not a 500), exactly the foundation contract
 * that the effector "drives the set + artifact statuses forward".
 *
 * <h3>Authorization</h3>
 * This effector carries NO authorization — authz (role + domain scope + the restore STEP-UP
 * gate) has already passed upstream in the foundation controller/service before
 * {@link #startBackup}/{@link #startRestore} is ever called. The brand-isolation SELECTORS the
 * factory bakes into the CR are defence-in-depth on TOP of that.
 */
@SuppressFBWarnings(value = "EI_EXPOSE_REP2",
        justification = "Spring constructor injection: the container owns this singleton collaborator and it is never mutated by this class after construction; a defensive copy of a bean is meaningless (not caller-owned mutable data).")
public class VeleroBackupEffector implements BackupEffector {

    private static final Logger log = LoggerFactory.getLogger(VeleroBackupEffector.class);

    /** Supplies a configured client; separated so it can be stubbed in tests (the
     *  {@code Fabric8JobLauncher.ClientFactory} idiom). */
    @FunctionalInterface
    public interface ClientFactory {
        KubernetesClient get();
    }

    /** The Velero CR ResourceDefinitionContext (velero.io/v1, namespaced). */
    private static final ResourceDefinitionContext BACKUP_RDC = new ResourceDefinitionContext.Builder()
            .withGroup("velero.io").withVersion("v1").withKind(VeleroResourceFactory.KIND_BACKUP)
            .withPlural("backups").withNamespaced(true).build();
    private static final ResourceDefinitionContext RESTORE_RDC = new ResourceDefinitionContext.Builder()
            .withGroup("velero.io").withVersion("v1").withKind(VeleroResourceFactory.KIND_RESTORE)
            .withPlural("restores").withNamespaced(true).build();

    private final ClientFactory clientFactory;
    private final VeleroResourceFactory factory;
    private final BackupSetRepository sets;

    public VeleroBackupEffector(ClientFactory clientFactory, VeleroResourceFactory factory,
                                BackupSetRepository sets) {
        this.clientFactory = clientFactory;
        this.factory = factory;
        this.sets = sets;
    }

    @Override
    public Mono<Void> startBackup(BackupSet set) {
        Mono<Void> applied = Mono.fromRunnable(() -> {
                    GenericKubernetesResource cr = factory.backup(set);
                    apply(BACKUP_RDC, cr);
                    log.info("[cloud-backup] Velero Backup CR '{}' applied (set id={} scope={} "
                                    + "domain={} storageLocation built) — backup queued",
                            cr.getMetadata().getName(), set.id(), set.scope(), set.domain());
                })
                .subscribeOn(Schedulers.boundedElastic())
                .then();
        // Backup launched -> the set is RUNNING (Velero reconciles it to complete/failed; a
        // future watch/sweep flips it terminal). Failure to apply -> the set is marked failed.
        // markStatus is DEFERRED so it is only invoked when the apply actually completed (the
        // error path never touches it).
        return applied
                .then(Mono.defer(() -> sets.markStatus(set.id(), BackupSet.STATUS_RUNNING, null).then()))
                .onErrorResume(t -> markFailed("backup", set, t));
    }

    @Override
    public Mono<Void> startRestore(BackupSet set) {
        Mono<Void> applied = Mono.fromRunnable(() -> {
                    GenericKubernetesResource cr = factory.restore(set);
                    apply(RESTORE_RDC, cr);
                    log.warn("[cloud-backup] Velero Restore CR '{}' applied (set id={} v={} "
                                    + "scope={} domain={}) — DESTRUCTIVE restore queued "
                                    + "(step-up was satisfied upstream)",
                            cr.getMetadata().getName(), set.id(), set.version(), set.scope(),
                            set.domain());
                })
                .subscribeOn(Schedulers.boundedElastic())
                .then();
        return applied.onErrorResume(t -> markFailed("restore", set, t));
    }

    /** Server-side-apply the CR into the Velero namespace via the generic resource API. The
     *  client is built lazily and closed per apply. */
    private void apply(ResourceDefinitionContext rdc, GenericKubernetesResource cr) {
        try (KubernetesClient client = clientFactory.get()) {
            client.genericKubernetesResources(rdc)
                    .inNamespace(factory.veleroNamespace())
                    .resource(cr)
                    .serverSideApply();
        }
    }

    /** Mark the set failed (best-effort) and SWALLOW the error to an empty Mono — the catalog
     *  records the failure; the create/restore request is not turned into a 500. */
    private Mono<Void> markFailed(String op, BackupSet set, Throwable t) {
        log.warn("[cloud-backup] Velero {} apply failed for set id={} domain={}: {}",
                op, set.id(), set.domain(), t.toString());
        return sets.markStatus(set.id(), BackupSet.STATUS_FAILED, null)
                .onErrorResume(e -> {
                    log.warn("[cloud-backup] could not mark set {} failed: {}", set.id(), e.toString());
                    return Mono.just(0L);
                })
                .then();
    }
}
