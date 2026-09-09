package net.hugmesh.adminbff.imagegen;

import io.fabric8.kubernetes.api.model.ConfigMap;
import io.fabric8.kubernetes.api.model.ConfigMapBuilder;
import io.fabric8.kubernetes.api.model.HasMetadata;
import io.fabric8.kubernetes.api.model.OwnerReference;
import io.fabric8.kubernetes.api.model.OwnerReferenceBuilder;
import io.fabric8.kubernetes.api.model.batch.v1.Job;
import io.fabric8.kubernetes.client.KubernetesClient;
import io.fabric8.kubernetes.client.KubernetesClientException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;
import net.hugmesh.commons.web.ApiException;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.util.List;

/**
 * The REAL image-gen launcher: applies the rendered manifest to the cluster with the
 * fabric8 {@code KubernetesClient} (already on the classpath via the
 * spring-cloud-kubernetes leader starter). The image-generation mirror of
 * {@link net.hugmesh.adminbff.testreports.Fabric8JobLauncher}.
 *
 * <p>Wired (see {@link ImageGenConfig}) ONLY when {@code imagegen.launch.enabled=true};
 * otherwise the {@link NoopImageJobLauncher} default is used so a cluster-less BFF still
 * exercises the full contract (SHIPS DARK). The Job is created with the {@code image-gen}
 * ServiceAccount declared in the manifest (least-privilege RBAC in
 * {@code jobs/image-gen-rbac.yaml}).
 *
 * <p><b>Two-doc apply is EXPLICITLY SEQUENTIAL</b> (spec channel, item 1b). fabric8's
 * multi-doc {@code load().create()} happens to create resources in document order (a
 * sequential stream over the parsed docs, aborting on the first failure — see
 * {@code NamespaceVisitFromServerGetWatchDeleteRecreateWaitApplicableListImpl.performOperation}
 * in kubernetes-client 7.4.1) but documents no such contract and never rolls back, so this
 * launcher parses the docs and drives the order itself:
 * <ol>
 *   <li>create the per-build spec ConfigMap FIRST — a rejection (e.g. missing RBAC) aborts
 *       the launch with NO Job left behind, so a spec build can never silently degrade to a
 *       legacy build;</li>
 *   <li>create the Job — on failure the just-created ConfigMap is deleted again
 *       (best-effort rollback) before the error propagates;</li>
 *   <li>PATCH the ConfigMap with an ownerReference to the created Job so the Job's
 *       {@code ttlSecondsAfterFinished} reap GC-CASCADES the ConfigMap. The ConfigMap is
 *       rendered before the Job exists, so it cannot carry the ownerReference up front.
 *       This patch is BEST-EFFORT: the build is already running when it happens, so a patch
 *       failure logs a warning and the launch still succeeds — a stale spec ConfigMap (non
 *       secret, reapable by name) is strictly better than killing a running build for
 *       cleanup wiring.</li>
 * </ol>
 *
 * <p>The {@code KubernetesClient} is supplied lazily by a {@link ClientFactory} so the bean
 * can be constructed (and the seam signal published) even though the client itself is created
 * on first apply — a transient API-server blip at startup must not fail the BFF boot. Its
 * acquire/apply/close lifecycle is expressed with {@code Mono.usingWhen} (acquire lazily,
 * apply, ALWAYS close — success, error, or cancellation — mirroring what try-with-resources
 * guaranteed), offloaded onto {@code Schedulers.boundedElastic()} since the fabric8 client
 * does blocking I/O; the games {@code Fabric8InstanceConfigMapWriter} is the in-repo precedent.
 * The three-step ordering above is UNAFFECTED: all three steps run inside one blocking
 * callable, so the sequencing and the best-effort rollback are exactly as before.
 */
public class Fabric8ImageJobLauncher implements ImageJobLauncher {

    private static final Logger log = LoggerFactory.getLogger(Fabric8ImageJobLauncher.class);

    /** Supplies a configured client; separated so it can be stubbed in tests. */
    @FunctionalInterface
    public interface ClientFactory {
        KubernetesClient get();
    }

    private final ClientFactory clientFactory;
    private final String namespace;

    public Fabric8ImageJobLauncher(ClientFactory clientFactory, String namespace) {
        this.clientFactory = clientFactory;
        this.namespace = (namespace == null || namespace.isBlank()) ? "hugmesh-backend" : namespace;
    }

    @Override
    public Mono<String> apply(String manifest, String buildId) {
        // Reactive resource lifecycle: Mono.usingWhen acquires the client LAZILY
        // (clientFactory::get), runs the EXPLICITLY SEQUENTIAL three-step applyBlocking, and
        // ALWAYS closes the client afterwards — success, error, or cancellation — the same
        // always-closes guarantee try-with-resources gave, expressed reactively.
        // subscribeOn(boundedElastic) keeps both the acquire (a DNS lookup / API-server
        // handshake) and the blocking applies off whichever thread subscribes, so the
        // offload is a property of the SEAM rather than something each call site must
        // remember. The ordering + rollback contract is unchanged: it all still happens
        // inside one blocking callable, so step 2 cannot begin before step 1 returns.
        return Mono.usingWhen(
                        Mono.fromCallable(clientFactory::get),
                        client -> Mono.fromCallable(() -> applyBlocking(client, manifest, buildId)),
                        client -> Mono.fromRunnable(client::close))
                .subscribeOn(Schedulers.boundedElastic())
                .onErrorMap(KubernetesClientException.class, e -> {
                    // A cluster-side rejection (RBAC, admission, conflict) is an operator-facing
                    // 502 — never a 500 that leaks a stack trace to the admin-ui.
                    log.warn("[imagegen] k8s apply for build {} failed: {}", buildId, e.getMessage());
                    return ApiException.badGateway("could not launch image-gen Job: " + e.getMessage());
                })
                .onErrorMap(e -> !(e instanceof ApiException), e -> {
                    log.warn("[imagegen] k8s apply for build {} errored: {}", buildId, e.toString());
                    return ApiException.badGateway("could not launch image-gen Job");
                });
    }

    /** The blocking three-step apply; the client's lifecycle is owned by {@link #apply}. */
    private String applyBlocking(KubernetesClient client, String manifest, String buildId)
            throws java.io.IOException {
        try (var stream = new ByteArrayInputStream(manifest.getBytes(StandardCharsets.UTF_8))) {
            // Parse only — load(...).items() unmarshals the docs locally, no API call yet.
            List<HasMetadata> items = client.load(stream).items();
            ConfigMap specConfigMap = null;
            Job job = null;
            for (HasMetadata item : items) {
                if (item instanceof ConfigMap cm) {
                    specConfigMap = cm;
                } else if (item instanceof Job j) {
                    job = j;
                } else {
                    // The renderer only ever emits [ConfigMap?, Job]; anything else means a
                    // poisoned/foreign manifest — fail closed before touching the cluster.
                    throw new IllegalStateException("unexpected document kind '"
                            + item.getKind() + "' in image-gen manifest");
                }
            }
            if (job == null) {
                throw new IllegalStateException("image-gen manifest carries no Job document");
            }

            // 1. Spec ConfigMap FIRST (order enforced HERE, not left to load().create()'s
            //    undocumented document-order behaviour): if this create is rejected, the
            //    launch aborts with NO Job created — never a spec build silently running legacy.
            ConfigMap createdConfigMap = specConfigMap == null ? null
                    : client.resource(specConfigMap).inNamespace(namespace).create();

            // 2. The Job. On failure, best-effort delete the ConfigMap we just created so a
            //    failed launch leaves nothing behind (the ownerRef reap never got wired).
            Job createdJob;
            try {
                createdJob = client.resource(job).inNamespace(namespace).create();
            } catch (RuntimeException e) {
                rollbackSpecConfigMap(client, createdConfigMap, buildId);
                throw e;
            }

            String name = createdJob.getMetadata() == null
                    ? "hugmesh-image-gen-" + buildId
                    : createdJob.getMetadata().getName();

            // 3. Best-effort ownerRef patch: Job reap (ttlSecondsAfterFinished) GC-cascades the
            //    ConfigMap. Failure logs + proceeds — the build is already running.
            ownSpecConfigMapByJob(client, createdConfigMap, createdJob, buildId);

            log.info("[imagegen] applied image-gen Job '{}' (build {}, spec ConfigMap: {}) in namespace {}",
                    name, buildId,
                    createdConfigMap == null ? "none (legacy)" : createdConfigMap.getMetadata().getName(),
                    namespace);
            return name;
        }
    }

    /**
     * PATCH the just-created spec ConfigMap with an ownerReference to the created Job
     * ({@code apiVersion: batch/v1, kind: Job, uid} from the create response) so the Job's
     * {@code ttlSecondsAfterFinished} reap GC-cascades the ConfigMap.
     *
     * <p>BEST-EFFORT by design: the Job is already running when this patch happens, so a
     * failure (RBAC drift, transient API blip) must not kill the build for cleanup wiring —
     * it logs a warning and returns normally. The un-owned ConfigMap is non-secret and
     * deterministically named ({@code hugmesh-image-spec-<buildId>}), so an operator can
     * always reap it by name.
     */
    private void ownSpecConfigMapByJob(KubernetesClient client, ConfigMap createdConfigMap,
                                       Job createdJob, String buildId) {
        if (createdConfigMap == null || createdConfigMap.getMetadata() == null) {
            return;
        }
        String cmName = createdConfigMap.getMetadata().getName();
        try {
            OwnerReference ownerRef = new OwnerReferenceBuilder()
                    .withApiVersion("batch/v1")
                    .withKind("Job")
                    .withName(createdJob.getMetadata().getName())
                    .withUid(createdJob.getMetadata().getUid())
                    .build();
            client.configMaps().inNamespace(namespace).withName(cmName)
                    .edit(cm -> new ConfigMapBuilder(cm)
                            .editMetadata().addToOwnerReferences(ownerRef).endMetadata()
                            .build());
        } catch (Exception e) {
            log.warn("[imagegen] best-effort ownerReference patch of spec ConfigMap '{}' (build {})"
                            + " failed — the ConfigMap will outlive the Job's TTL reap until removed"
                            + " by name: {}",
                    cmName, buildId, e.toString());
        }
    }

    /** Best-effort delete of the spec ConfigMap created by a launch whose Job create then
     *  failed — the ownerRef reap never got wired, so without this the ConfigMap would leak. */
    private void rollbackSpecConfigMap(KubernetesClient client, ConfigMap createdConfigMap,
                                       String buildId) {
        if (createdConfigMap == null || createdConfigMap.getMetadata() == null) {
            return;
        }
        String cmName = createdConfigMap.getMetadata().getName();
        try {
            client.configMaps().inNamespace(namespace).withName(cmName).delete();
            log.info("[imagegen] rolled back spec ConfigMap '{}' after failed Job create (build {})",
                    cmName, buildId);
        } catch (Exception e) {
            log.warn("[imagegen] rollback delete of spec ConfigMap '{}' (build {}) failed: {}",
                    cmName, buildId, e.toString());
        }
    }

    @Override
    public boolean isReal() {
        return true;
    }
}
