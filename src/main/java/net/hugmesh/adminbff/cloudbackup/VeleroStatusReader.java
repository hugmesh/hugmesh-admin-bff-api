package net.hugmesh.adminbff.cloudbackup;

import reactor.core.publisher.Flux;

/**
 * The read-only seam the {@link BackupStatusReconciler} sweeps through — lists the Velero
 * ({@code velero.io/v1}) {@code Backup} + {@code Restore} CRs (in the Velero namespace) that the
 * effector emitted, projected to the fabric8-free {@link VeleroCr}. Mirrors the
 * {@code WorkloadClient} / {@code RunningServiceProvider} seam idiom: a thin abstraction so the
 * reconcile LOGIC (CR→set mapping, terminal classification, idempotent status write) is unit-
 * testable by mocking THIS interface — never the heavyweight fabric8 {@code KubernetesClient}.
 *
 * <p><b>READ-ONLY.</b> This seam ONLY reads CR status; it NEVER applies/mutates a CR and NEVER
 * touches credentials or secrets. The status WRITE goes to the BFF's sole-writer
 * {@code BackupSetRepository.markStatus}, not back to the cluster.
 *
 * <p><b>SHIPS DARK.</b> The default {@link NoopVeleroStatusReader} returns an empty stream and
 * dials no cluster. The real {@code Fabric8VeleroStatusReader} is wired ONLY when
 * {@code app.backups.effector.enabled=true} (the SAME flag as the effector), so with the flag off
 * (the default) nothing here lists CRs.
 */
public interface VeleroStatusReader {

    /**
     * List the Velero {@code Backup} + {@code Restore} CRs the effector emitted (those carrying the
     * {@code app.kubernetes.io/managed-by=hugmesh-admin-bff} stamp), projected to {@link
     * VeleroCr}. The reconciler filters to {@link VeleroCr#isTerminal()} itself, so an
     * implementation MAY return non-terminal CRs too (the dark default returns nothing).
     */
    Flux<VeleroCr> listManagedBackupsAndRestores();
}
