package net.hugmesh.adminbff.cloudbackup;

import io.fabric8.kubernetes.api.model.GenericKubernetesResource;
import io.fabric8.kubernetes.api.model.GenericKubernetesResourceList;
import io.fabric8.kubernetes.client.KubernetesClient;
import io.fabric8.kubernetes.client.dsl.base.ResourceDefinitionContext;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * The REAL {@link VeleroStatusReader}: lists the Velero ({@code velero.io/v1}) {@code Backup} +
 * {@code Restore} CRs the effector emitted (filtered to the BFF's
 * {@code app.kubernetes.io/managed-by=hugmesh-admin-bff} stamp) via the fabric8
 * {@link KubernetesClient}, and projects each to the fabric8-free {@link VeleroCr}. Mirrors the
 * effector's {@code VeleroBackupEffector} / games {@code Fabric8InstanceConfigMapWriter} style: the
 * blocking fabric8 list runs on {@code boundedElastic} (the reactive boundary) and the
 * {@link KubernetesClient} is supplied LAZILY by a {@link ClientFactory} (built per read, not at
 * boot) so a transient API-server blip never bricks BFF boot — only a sweep touches the API server.
 *
 * <h3>READ-ONLY</h3>
 * Lists CR status ONLY. NEVER applies/mutates a CR, NEVER reads or handles credentials/secrets. The
 * status write is the BFF's sole-writer {@code BackupSetRepository.markStatus} — this reader hands
 * the reconciler an immutable projection and stops there.
 *
 * <h3>Phase source: {@code .status.phase} (primary) + the generator's mirror annotation (fallback)</h3>
 * The terminal outcome is read DIRECTLY from the Velero CR {@code .status.phase}
 * ({@code Completed} / {@code PartiallyFailed} / {@code Failed} / ...). That is the authoritative,
 * always-present field Velero itself writes, independent of whether the generator's optional
 * status-mirror CronJob (#120) has run, so it is the more robust source. The generator CronJob
 * additionally stamps {@code hugmesh.net/catalog-status} mirroring the terminal phase; this
 * reader uses that annotation ONLY as a fallback when {@code .status.phase} is somehow absent, so
 * the sweep works WITH or WITHOUT that CronJob deployed.
 */
public class Fabric8VeleroStatusReader implements VeleroStatusReader {

    /** Mirrors {@code VeleroBackupEffector.ClientFactory}: supplies a configured client, stubbable
     *  in tests. */
    @FunctionalInterface
    public interface ClientFactory {
        KubernetesClient get();
    }

    /** The {@code app.kubernetes.io/managed-by} label the effector stamps on every CR it builds —
     *  the sweep only ever looks at CRs the BFF emitted (never a hand-made or third-party Velero
     *  Backup). */
    static final String MANAGED_BY_LABEL = "app.kubernetes.io/managed-by";
    static final String MANAGED_BY_VALUE = "hugmesh-admin-bff";

    /** The generator's status-mirror annotation (#120) — a FALLBACK phase source only. */
    static final String CATALOG_STATUS_ANNOTATION = "hugmesh.net/catalog-status";

    private static final ResourceDefinitionContext BACKUP_RDC = new ResourceDefinitionContext.Builder()
            .withGroup("velero.io").withVersion("v1").withKind("Backup")
            .withPlural("backups").withNamespaced(true).build();
    private static final ResourceDefinitionContext RESTORE_RDC = new ResourceDefinitionContext.Builder()
            .withGroup("velero.io").withVersion("v1").withKind("Restore")
            .withPlural("restores").withNamespaced(true).build();

    private final ClientFactory clientFactory;
    private final String veleroNamespace;

    public Fabric8VeleroStatusReader(ClientFactory clientFactory, String veleroNamespace) {
        this.clientFactory = clientFactory;
        this.veleroNamespace = (veleroNamespace == null || veleroNamespace.isBlank())
                ? "velero" : veleroNamespace.trim();
    }

    @Override
    public Flux<VeleroCr> listManagedBackupsAndRestores() {
        return Mono.fromCallable(this::listBlocking)
                .subscribeOn(Schedulers.boundedElastic())
                .flatMapMany(Flux::fromIterable);
    }

    /** The blocking fabric8 read — both CR kinds in the Velero namespace, filtered to the BFF's
     *  managed-by stamp. The client is built lazily and closed per sweep. */
    private List<VeleroCr> listBlocking() {
        List<VeleroCr> out = new ArrayList<>();
        try (KubernetesClient client = clientFactory.get()) {
            collect(client, BACKUP_RDC, "Backup", out);
            collect(client, RESTORE_RDC, "Restore", out);
        }
        return out;
    }

    private void collect(KubernetesClient client, ResourceDefinitionContext rdc, String kind,
                         List<VeleroCr> out) {
        GenericKubernetesResourceList list = client.genericKubernetesResources(rdc)
                .inNamespace(veleroNamespace)
                .withLabel(MANAGED_BY_LABEL, MANAGED_BY_VALUE)
                .list();
        if (list == null || list.getItems() == null) {
            return;
        }
        for (GenericKubernetesResource cr : list.getItems()) {
            out.add(project(kind, cr));
        }
    }

    /** Project one fabric8 CR to the pure {@link VeleroCr}: the name, the {@code .status.phase}
     *  (falling back to the generator's mirror annotation), and the set-id annotation + label. */
    private static VeleroCr project(String kind, GenericKubernetesResource cr) {
        String name = cr.getMetadata() == null ? null : cr.getMetadata().getName();
        Map<String, String> labels = cr.getMetadata() == null ? null : cr.getMetadata().getLabels();
        Map<String, String> annotations =
                cr.getMetadata() == null ? null : cr.getMetadata().getAnnotations();

        String phase = statusPhase(cr);
        if (phase == null || phase.isBlank()) {
            // Fallback: the generator CronJob's mirrored terminal status, if present.
            phase = annotations == null ? null : annotations.get(CATALOG_STATUS_ANNOTATION);
        }

        String setIdAnnotation = annotations == null ? null : annotations.get(VeleroCr.SET_ID_ANNOTATION);
        String setIdLabel = labels == null ? null : labels.get(VeleroCr.SET_ID_LABEL);
        return new VeleroCr(kind, name, phase, setIdAnnotation, setIdLabel);
    }

    /** Read {@code .status.phase} from the CR's additional properties (the generic-resource model
     *  carries {@code spec}/{@code status} as untyped maps). Null when there is no status yet. */
    @SuppressWarnings("unchecked")
    private static String statusPhase(GenericKubernetesResource cr) {
        Object status = cr.getAdditionalProperties() == null
                ? null : cr.getAdditionalProperties().get("status");
        if (status instanceof Map<?, ?> m) {
            Object phase = ((Map<String, Object>) m).get("phase");
            return phase == null ? null : phase.toString();
        }
        return null;
    }
}
