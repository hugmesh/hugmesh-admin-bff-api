package net.hugmesh.adminbff.cloudbackup;

import reactor.core.publisher.Mono;

/**
 * The seam to the real BACKUP / RESTORE worker (Velero + a kopia/restic AES repo). The
 * FOUNDATION leg records the catalog row and then hands the set off to this effector; the
 * effector is what actually runs the Velero backup/restore Job.
 *
 * <p><b>SHIPS DARK.</b> The default {@link NoopBackupEffector} does NOTHING (logs + returns) —
 * a created backup_set sits at {@code pending} and no real Velero job is emitted. The
 * generator (Velero) leg supplies the real effector behind this interface, which is the
 * CONTRACT a follow-on leg must provide:
 * <ul>
 *   <li>{@link #startBackup(BackupSet)} — launch the Velero backup for the set (db_dump /
 *       pv_snapshot / config per artifact), write to the set's destination, encrypt with the
 *       repo key referenced by {@code encryptionMeta}, and drive the set + artifact statuses
 *       forward (running -> complete/failed) via the repositories.</li>
 *   <li>{@link #startRestore(BackupSet)} — restore the set's version to the cluster (the
 *       PRIVILEGED, step-up-gated path; authz has already passed upstream).</li>
 * </ul>
 */
public interface BackupEffector {

    /** Launch the real backup for the set. The default Noop is dark. */
    Mono<Void> startBackup(BackupSet set);

    /** Launch the real restore of the set's version. The default Noop is dark. */
    Mono<Void> startRestore(BackupSet set);
}
