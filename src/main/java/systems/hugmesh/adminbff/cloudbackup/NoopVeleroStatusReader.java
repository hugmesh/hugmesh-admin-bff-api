package systems.hugmesh.adminbff.cloudbackup;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import reactor.core.publisher.Flux;

/**
 * The DEFAULT, DARK {@link VeleroStatusReader}: returns an EMPTY stream and dials no cluster. In
 * force whenever the Velero effector is not enabled ({@code app.backups.effector.enabled} off — the
 * dev/test/CI default and every deployment until the generator/Velero leg ships), mirroring the
 * foundation's {@code NoopBackupEffector} / games {@code NoopInstanceConfigMapWriter}.
 *
 * <p>With this reader in force the {@link BackupStatusReconciler} (if even constructed) reconciles
 * an empty CR set — a guaranteed no-op, so the status-sweep feature SHIPS DARK exactly like the
 * effector it closes the loop for. In practice the reconciler bean itself is also gated off the
 * same flag, so neither the reconciler nor a real reader exists by default.
 */
public class NoopVeleroStatusReader implements VeleroStatusReader {

    private static final Logger log = LoggerFactory.getLogger(NoopVeleroStatusReader.class);

    @Override
    public Flux<VeleroCr> listManagedBackupsAndRestores() {
        log.debug("[cloud-backup] SHIPS DARK — no Velero status reader wired; sweep reads no CRs");
        return Flux.empty();
    }
}
