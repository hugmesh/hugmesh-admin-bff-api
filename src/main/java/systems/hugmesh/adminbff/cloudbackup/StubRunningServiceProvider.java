package systems.hugmesh.adminbff.cloudbackup;

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Flux;
import systems.hugmesh.commons.security.PrincipalDomain;

import java.util.List;

/**
 * The DEFAULT {@link RunningServiceProvider} for the FOUNDATION leg — a DOCUMENTED STUB that
 * returns the platform's installed-services list (the same closed vocabulary the legacy USB
 * {@code BackupScope} captures, PLUS the optional add-by-command services the platform can
 * run per brand). It does NOT consult a live cluster.
 *
 * <p>The generator/Velero leg's {@code ConfigMapRunningServiceProvider} replaces this stub
 * (reading the per-brand installed-services ConfigMap) when {@code app.backups.effector.enabled}
 * is true. This stub stays the bean by default (and remains the catalog VOCABULARY the real
 * provider filters against — it is the single source of truth for service kinds/labels).
 *
 * <p><b>Dark by default.</b> {@link ConditionalOnProperty} (DEFAULT, matchIfMissing) keeps this
 * stub the bean whenever the effector flag is false/absent and deterministically yields to the
 * real provider (gated on the SAME flag's {@code true} branch) when on — the {@code
 * TestReportsConfig} mutually-exclusive-property idiom, so exactly ONE {@link RunningServiceProvider}
 * registers in every mode.
 *
 * <p>The list is the SAME for every scope here (the stub has no per-brand knowledge); the real
 * provider filters by {@link PrincipalDomain#domain()}.
 */
@Component
@ConditionalOnProperty(name = "app.backups.effector.enabled", havingValue = "false",
        matchIfMissing = true)
public class StubRunningServiceProvider implements RunningServiceProvider {

    /** The CORE platform services (always present). Mirrors the legacy {@code BackupScope}
     *  vocabulary (etcd/secrets/postgres/pvc/config) so the worker's understanding of a
     *  service is consistent across the USB and cloud backup paths. */
    private static final List<RunningService> CORE = List.of(
            new RunningService("etcd", "Cluster etcd", BackupArtifact.KIND_PV_SNAPSHOT, false),
            new RunningService("secrets", "Kubernetes Secrets", BackupArtifact.KIND_CONFIG, false),
            new RunningService("postgres", "Platform Postgres", BackupArtifact.KIND_DB_DUMP, false),
            new RunningService("pvc", "PersistentVolume data", BackupArtifact.KIND_PV_SNAPSHOT, false),
            new RunningService("config", "ConfigMaps / manifests", BackupArtifact.KIND_CONFIG, false),
            new RunningService("casdoor", "Casdoor (IdP)", BackupArtifact.KIND_DB_DUMP, false));

    /** The OPTIONAL add/remove-by-command services (greyed-out when not installed; a real
     *  provider omits an absent one). */
    private static final List<RunningService> OPTIONAL = List.of(
            new RunningService("matrix", "Matrix homeserver", BackupArtifact.KIND_PV_SNAPSHOT, true),
            new RunningService("akkoma", "Akkoma (Fediverse)", BackupArtifact.KIND_DB_DUMP, true),
            new RunningService("phpbb", "phpBB forum", BackupArtifact.KIND_DB_DUMP, true),
            new RunningService("games", "Games app-store servers", BackupArtifact.KIND_PV_SNAPSHOT, true),
            new RunningService("tube", "LocalTube", BackupArtifact.KIND_PV_SNAPSHOT, true),
            new RunningService("owncast", "Owncast streaming", BackupArtifact.KIND_PV_SNAPSHOT, true));

    @Override
    public Flux<RunningService> runningServices(PrincipalDomain scope) {
        // The stub returns the documented installed-services list regardless of scope. A real
        // ConfigMap/namespace-backed provider filters to the caller's brand.
        return Flux.fromIterable(CORE).concatWith(Flux.fromIterable(OPTIONAL));
    }
}
