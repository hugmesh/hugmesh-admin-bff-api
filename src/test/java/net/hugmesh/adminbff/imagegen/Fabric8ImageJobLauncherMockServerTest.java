package net.hugmesh.adminbff.imagegen;

import io.fabric8.kubernetes.api.model.ConfigMap;
import io.fabric8.kubernetes.api.model.OwnerReference;
import io.fabric8.kubernetes.api.model.batch.v1.Job;
import io.fabric8.kubernetes.client.KubernetesClient;
import io.fabric8.kubernetes.client.server.mock.EnableKubernetesMockClient;
import io.fabric8.kubernetes.client.server.mock.KubernetesMockServer;
import org.junit.jupiter.api.Test;
import net.hugmesh.adminbff.sshterminal.ImageBuild;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The REAL two-doc apply contract against the fabric8 CRUD mock server (no cluster):
 * <ul>
 *   <li>spec build → the per-build {@code hugmesh-image-spec-<id>} ConfigMap AND the Job
 *       both exist after {@code apply()}, and the ConfigMap has been PATCHed with an
 *       ownerReference ({@code batch/v1 Job}, uid of the created Job) so the Job's
 *       {@code ttlSecondsAfterFinished} reap GC-cascades it;</li>
 *   <li>legacy build → the single-doc manifest creates the Job alone, no ConfigMap.</li>
 * </ul>
 * The manifests are rendered by the REAL {@link ImageBuildOrchestrator#renderManifest}, so
 * this exercises the exact bytes a live launch would apply. Failure-path ordering (ConfigMap
 * rejection, Job rollback) is pinned by {@link Fabric8ImageJobLauncherFailurePathTest}.
 */
@EnableKubernetesMockClient(crud = true)
class Fabric8ImageJobLauncherMockServerTest {

    private static final String NS = "hugmesh-backend";
    private static final String BUILD_ID = "00000000-0000-0000-0000-000000000042";

    // Injected by the fabric8 JUnit5 extension (fresh mock server per test).
    KubernetesMockServer server;
    KubernetesClient client;

    // renderManifest never touches the repo, so a null repo is fine (render-only use).
    private final ImageBuildOrchestrator renderer =
            new ImageBuildOrchestrator(null, new NoopImageJobLauncher(), 8);

    private static ImageBuild build(String spec) {
        return new ImageBuild(BUILD_ID, null, "admin@x", "brandx/alice", "brandx",
                ImageBuild.IMAGE_PRIMARY, "rpi5", null, ImageBuild.STATUS_QUEUED, true,
                null, null, null, null, null, null, spec);
    }

    private Fabric8ImageJobLauncher launcher() {
        // A FRESH client per apply — the launcher closes its client (try-with-resources),
        // and the extension-injected `client` must stay open for the assertions below.
        return new Fabric8ImageJobLauncher(() -> server.createClient(), NS);
    }

    @Test
    void specBuild_appliesConfigMapAndJob_andPatchesOwnerReference() {
        String spec = "{\"role\":\"gateway\",\"platform\":\"rpi5\",\"hostname\":\"gw\"}";
        String manifest = renderer.renderManifest(build(spec));

        String jobName = launcher().apply(manifest, BUILD_ID);

        assertThat(jobName).isEqualTo("hugmesh-image-gen-" + BUILD_ID);
        Job job = client.batch().v1().jobs().inNamespace(NS).withName(jobName).get();
        assertThat(job).as("Job created").isNotNull();

        ConfigMap cm = client.configMaps().inNamespace(NS)
                .withName("hugmesh-image-spec-" + BUILD_ID).get();
        assertThat(cm).as("spec ConfigMap created").isNotNull();
        assertThat(cm.getData()).containsKey("spec.json");
        assertThat(cm.getData().get("spec.json")).contains("\"role\":\"gateway\"");

        // The ownerReference PATCH: Job reap must GC-cascade this ConfigMap.
        assertThat(cm.getMetadata().getOwnerReferences()).hasSize(1);
        OwnerReference ref = cm.getMetadata().getOwnerReferences().get(0);
        assertThat(ref.getApiVersion()).isEqualTo("batch/v1");
        assertThat(ref.getKind()).isEqualTo("Job");
        assertThat(ref.getName()).isEqualTo(jobName);
        assertThat(ref.getUid()).isNotBlank().isEqualTo(job.getMetadata().getUid());
    }

    @Test
    void legacyBuild_appliesJobOnly_noConfigMap() {
        String manifest = renderer.renderManifest(build(null));

        String jobName = launcher().apply(manifest, BUILD_ID);

        assertThat(jobName).isEqualTo("hugmesh-image-gen-" + BUILD_ID);
        assertThat(client.batch().v1().jobs().inNamespace(NS).withName(jobName).get()).isNotNull();
        assertThat(client.configMaps().inNamespace(NS)
                .withName("hugmesh-image-spec-" + BUILD_ID).get())
                .as("no spec ConfigMap for a legacy build").isNull();
    }
}
