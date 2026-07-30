package systems.hugmesh.adminbff.cloudbackup;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

/**
 * The DEFAULT, DARK {@link BackupEffector}. With no real Velero effector wired (the
 * cluster-less dev/test/CI default, AND every deployment until the generator/Velero leg ships
 * the real one), {@link #startBackup}/{@link #startRestore} do NOTHING but log — the catalog
 * row is written by the service, but no Velero Job is emitted, so the feature SHIPS DARK
 * exactly like {@code service_deployment}'s stubbed ArgoCD effect and the workload-console
 * GitOps emitter.
 *
 * <p><b>Dark by default.</b> {@link ConditionalOnProperty} (DEFAULT, matchIfMissing) keeps this
 * Noop the bean whenever {@code app.backups.effector.enabled} is false/absent, and
 * deterministically yields to the real {@code VeleroBackupEffector} (gated on the SAME flag's
 * {@code true} branch) when the flag is on. This is the {@code TestReportsConfig}/{@code
 * GamesReconcilerConfig} mutually-exclusive-property idiom — exactly ONE {@link BackupEffector}
 * registers in every mode (a cross-source {@code @ConditionalOnMissingBean} alone cannot
 * guarantee that, per the {@code TestReportsConfig} note).
 */
@Component
@ConditionalOnProperty(name = "app.backups.effector.enabled", havingValue = "false",
        matchIfMissing = true)
public class NoopBackupEffector implements BackupEffector {

    private static final Logger log = LoggerFactory.getLogger(NoopBackupEffector.class);

    @Override
    public Mono<Void> startBackup(BackupSet set) {
        log.info("[cloud-backup] SHIPS DARK — no Velero effector wired; backup set id={} "
                + "scope={} domain={} stays pending (no Job emitted)",
                set.id(), set.scope(), set.domain());
        return Mono.empty();
    }

    @Override
    public Mono<Void> startRestore(BackupSet set) {
        log.info("[cloud-backup] SHIPS DARK — no Velero effector wired; restore of set id={} "
                + "version={} domain={} is a no-op (no Job emitted)",
                set.id(), set.version(), set.domain());
        return Mono.empty();
    }
}
