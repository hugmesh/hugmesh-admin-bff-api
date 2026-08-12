package net.hugmesh.adminbff.cloudbackup;

import io.fabric8.kubernetes.client.KubernetesClientBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import net.hugmesh.adminbff.lease.LeaderElection;

/**
 * Wires the {@link BackupStatusReconciler} (the catalog-write status sweep) + its
 * {@link VeleroStatusReader}, gated behind the SAME flag as the effector,
 * {@code app.backups.effector.enabled} (DEFAULT false). Mirrors {@code GamesReconcilerConfig} /
 * {@code BackupEffectorConfig} EXACTLY (the {@code @ConditionalOnProperty} idiom + the lazy fabric8
 * {@code KubernetesClient} supplier so a missing in-cluster context never fails BFF boot).
 *
 * <h3>SHIPS DARK (the reconciler bean is ABSENT by default)</h3>
 * With the flag OFF (the DEFAULT — every dev/test/CI run and every deployment until the
 * generator/Velero leg provisions Velero) NEITHER the {@link BackupStatusReconciler} NOR the real
 * {@link Fabric8VeleroStatusReader} is created: only the dark {@link NoopVeleroStatusReader} is
 * registered, and no {@code @Scheduled} sweep exists, so NOTHING lists Velero CRs or dials a
 * cluster. Flipping {@code app.backups.effector.enabled=true} swaps in the fabric8 reader AND
 * registers the scheduled reconciler. The {@link BackupStatusReconcilerWiringTest} pins this.
 *
 * <p>The reconciler is gated on the SAME flag the effector uses on purpose: the sweep only has work
 * to do when the effector is actually emitting CRs, so the two halves of the loop dark/light
 * together off one switch.
 *
 * <h3>Single-writer</h3>
 * The reconciler injects the platform-wide {@link LeaderElection} bean ({@code AlwaysLeader} by
 * default; the k8s {@code Lease} when {@code app.access-suspension.lease.enabled=true}) — the SAME
 * single-writer primitive the suspension + games reconcile loops use, so at most one replica sweeps
 * at a time. (The reconciler's pre-read {@code isTerminal} skip plus its value-idempotent status
 * write make it safe even without the Lease.)
 */
@Configuration(proxyBeanMethods = false)
public class BackupStatusReconcilerConfig {

    private static final Logger log = LoggerFactory.getLogger(BackupStatusReconcilerConfig.class);

    /** Cluster-less DARK default — the empty reader, used whenever the effector is not enabled. */
    @Bean
    @ConditionalOnProperty(name = "app.backups.effector.enabled", havingValue = "false",
            matchIfMissing = true)
    VeleroStatusReader noopVeleroStatusReader() {
        return new NoopVeleroStatusReader();
    }

    /** The REAL fabric8-backed reader — wired ONLY when the effector is enabled. Reads the SAME
     *  Velero namespace the effector applies into ({@code app.backups.effector.velero-namespace}). */
    @Bean
    @ConditionalOnProperty(name = "app.backups.effector.enabled", havingValue = "true")
    VeleroStatusReader fabric8VeleroStatusReader(
            @Value("${app.backups.effector.velero-namespace:velero}") String veleroNamespace) {
        Fabric8VeleroStatusReader.ClientFactory clientFactory =
                () -> new KubernetesClientBuilder().build();
        log.info("[cloud-backup-reconciler] Velero status reader ENABLED (veleroNamespace={})",
                veleroNamespace);
        return new Fabric8VeleroStatusReader(clientFactory, veleroNamespace);
    }

    /** The scheduled status-sweep reconciler — registered ONLY when the effector is enabled, so the
     *  {@code @Scheduled} tick does not even exist by default (the bean is absent). */
    @Bean
    @ConditionalOnProperty(name = "app.backups.effector.enabled", havingValue = "true")
    BackupStatusReconciler backupStatusReconciler(VeleroStatusReader reader,
                                                  BackupSetRepository sets,
                                                  LeaderElection leader) {
        log.info("[cloud-backup-reconciler] status sweep ENABLED (single-writer via {})",
                leader.label());
        return new BackupStatusReconciler(reader, sets, leader);
    }
}
