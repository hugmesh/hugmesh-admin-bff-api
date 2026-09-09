package net.hugmesh.adminbff.imagegen;

import io.fabric8.kubernetes.api.model.ConfigMap;
import io.fabric8.kubernetes.api.model.DeletionPropagation;
import io.fabric8.kubernetes.api.model.OwnerReference;
import io.fabric8.kubernetes.api.model.batch.v1.Job;
import io.fabric8.kubernetes.client.Config;
import io.fabric8.kubernetes.client.ConfigBuilder;
import io.fabric8.kubernetes.client.KubernetesClient;
import io.fabric8.kubernetes.client.KubernetesClientBuilder;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import net.hugmesh.adminbff.sshterminal.ImageBuild;
import net.hugmesh.commons.web.ApiException;

import java.time.Duration;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * LIVE-CLUSTER e2e of the image-gen spec channel — SHIPS DARK. Gated on
 * {@code IMAGEGEN_KIND_E2E=true}; a plain {@code ./mvnw test} run SKIPS this class entirely
 * (offline-safe, no kubeconfig touched). When enabled it drives the REAL path against the
 * ambient kubeconfig cluster (kind):
 * <ol>
 *   <li>render a spec-carrying manifest via the REAL
 *       {@link ImageBuildOrchestrator#renderManifest};</li>
 *   <li>apply it via a REAL {@link Fabric8ImageJobLauncher} (fabric8 auto-config from the
 *       ambient kubeconfig);</li>
 *   <li>assert the per-build spec ConfigMap AND the Job exist, and the ConfigMap carries the
 *       {@code batch/v1 Job} ownerReference (uid of the created Job);</li>
 *   <li>delete the Job (background propagation, the same cascade the
 *       {@code ttlSecondsAfterFinished} reap uses) and poll ≤90s that the GARBAGE COLLECTOR
 *       removed the ConfigMap — the no-leak invariant;</li>
 *   <li>NEGATIVE leg: impersonating a principal WITHOUT the configmaps grant (the
 *       {@code image-gen} runner SA, which per {@code jobs/image-gen-rbac.yaml} holds no API
 *       grants at all), the apply FAILS CLOSED on the ConfigMap create — the FIRST call — and
 *       leaves NO Job behind (the ConfigMap-before-Job ordering, proven live).</li>
 * </ol>
 *
 * <p>PREREQUISITES on the target cluster: namespace {@code hugmesh-backend} exists and
 * {@code jobs/image-gen-rbac.yaml} is applied (ServiceAccount {@code image-gen} + the
 * launcher Role/RoleBinding — the ambient kubeconfig user must itself be allowed to create
 * Jobs/ConfigMaps there and to impersonate the runner SA; kind's admin context is).
 *
 * <p>TEST-ONLY manifest post-processing (the repo manifest stays untouched): a cluster that
 * lacks the real image-gen image can still run the pod via
 * <ul>
 *   <li>{@code IMAGEGEN_KIND_E2E_IMAGE} — replaces the builder image reference;</li>
 *   <li>{@code IMAGEGEN_KIND_E2E_COMMAND} — replaces the builder command with
 *       {@code /bin/sh -c '<value>'} (e.g. {@code sleep 30}).</li>
 * </ul>
 * Neither is required for the assertions here (they cover object existence + GC, not pod
 * success — a Pending/ImagePullBackOff pod does not fail this test).
 */
@EnabledIfEnvironmentVariable(named = "IMAGEGEN_KIND_E2E", matches = "true")
class ImageGenKindE2eTest {

    private static final String NS = "hugmesh-backend";
    private static final Duration GC_TIMEOUT = Duration.ofSeconds(90);

    private final ImageBuildOrchestrator renderer =
            new ImageBuildOrchestrator(null, new NoopImageJobLauncher(), 8);

    private static ImageBuild specBuild(String buildId) {
        return new ImageBuild(buildId, null, "e2e@kind", "brandx/alice", "brandx",
                ImageBuild.IMAGE_PRIMARY, "rpi5", null, ImageBuild.STATUS_QUEUED, true,
                null, null, null, null, null, null,
                "{\"role\":\"gateway\",\"platform\":\"rpi5\",\"hostname\":\"e2e\"}");
    }

    /** TEST-ONLY overrides (image / command) — never applied outside this class. */
    private static String applyTestOnlyOverrides(String manifest) {
        String image = System.getenv("IMAGEGEN_KIND_E2E_IMAGE");
        if (image != null && !image.isBlank()) {
            manifest = manifest.replace(
                    "image: registry.hugmesh.net/hugmesh/image-gen:latest",
                    "image: " + image);
        }
        String command = System.getenv("IMAGEGEN_KIND_E2E_COMMAND");
        if (command != null && !command.isBlank()) {
            manifest = manifest.replace(
                    "command: [\"/bin/sh\", \"/builder/build-image.sh\"]",
                    "command: [\"/bin/sh\", \"-c\", '" + command.replace("'", "''") + "']");
        }
        return manifest;
    }

    @Test
    void specChannel_apply_ownerRef_andGcCascade() throws Exception {
        String buildId = UUID.randomUUID().toString();
        String cmName = "hugmesh-image-spec-" + buildId;
        String manifest = applyTestOnlyOverrides(renderer.renderManifest(specBuild(buildId)));

        Fabric8ImageJobLauncher launcher = new Fabric8ImageJobLauncher(
                () -> new KubernetesClientBuilder().build(), NS);
        String jobName = launcher.apply(manifest, buildId).block();

        try (KubernetesClient client = new KubernetesClientBuilder().build()) {
            try {
                Job job = client.batch().v1().jobs().inNamespace(NS).withName(jobName).get();
                assertThat(job).as("Job exists after apply").isNotNull();

                ConfigMap cm = client.configMaps().inNamespace(NS).withName(cmName).get();
                assertThat(cm).as("spec ConfigMap exists after apply").isNotNull();
                assertThat(cm.getData()).containsKey("spec.json");
                assertThat(cm.getMetadata().getOwnerReferences())
                        .as("ownerReference patched onto the spec ConfigMap").hasSize(1);
                OwnerReference ref = cm.getMetadata().getOwnerReferences().get(0);
                assertThat(ref.getApiVersion()).isEqualTo("batch/v1");
                assertThat(ref.getKind()).isEqualTo("Job");
                assertThat(ref.getName()).isEqualTo(jobName);
                assertThat(ref.getUid()).isEqualTo(job.getMetadata().getUid());

                // Reap the Job the way ttlSecondsAfterFinished would (background cascade) and
                // let the garbage collector prove the no-leak invariant.
                client.batch().v1().jobs().inNamespace(NS).withName(jobName)
                        .withPropagationPolicy(DeletionPropagation.BACKGROUND).delete();

                boolean gone = false;
                long deadline = System.nanoTime() + GC_TIMEOUT.toNanos();
                while (System.nanoTime() < deadline) {
                    if (client.configMaps().inNamespace(NS).withName(cmName).get() == null) {
                        gone = true;
                        break;
                    }
                    Thread.sleep(1_000);
                }
                assertThat(gone)
                        .as("GC cascade removed spec ConfigMap '%s' within %ss", cmName,
                                GC_TIMEOUT.toSeconds())
                        .isTrue();
            } finally {
                // Best-effort cleanup so a failed assertion never litters the cluster.
                try {
                    client.batch().v1().jobs().inNamespace(NS).withName(jobName)
                            .withPropagationPolicy(DeletionPropagation.BACKGROUND).delete();
                } catch (Exception ignored) { /* already gone */ }
                try {
                    client.configMaps().inNamespace(NS).withName(cmName).delete();
                } catch (Exception ignored) { /* already gone */ }
            }
        }
    }

    @Test
    void withoutConfigMapGrant_applyFailsClosed_andLeavesNoJob() {
        String buildId = UUID.randomUUID().toString();
        String manifest = applyTestOnlyOverrides(renderer.renderManifest(specBuild(buildId)));

        // Impersonate the image-gen RUNNER SA: per jobs/image-gen-rbac.yaml it holds NO API
        // grants — in particular no configmaps create — so the FIRST call of the two-doc apply
        // (the ConfigMap create) is rejected and the fail-closed ordering must leave NO Job.
        Fabric8ImageJobLauncher ungranted = new Fabric8ImageJobLauncher(() -> {
            Config cfg = new ConfigBuilder(Config.autoConfigure(null))
                    .withImpersonateUsername("system:serviceaccount:" + NS + ":image-gen")
                    .withImpersonateGroups("system:serviceaccounts", "system:authenticated")
                    .build();
            return new KubernetesClientBuilder().withConfig(cfg).build();
        }, NS);

        assertThatThrownBy(() -> ungranted.apply(manifest, buildId).block())
                .isInstanceOf(ApiException.class)
                .hasMessageContaining("could not launch image-gen Job");

        try (KubernetesClient client = new KubernetesClientBuilder().build()) {
            assertThat(client.batch().v1().jobs().inNamespace(NS)
                    .withName("hugmesh-image-gen-" + buildId).get())
                    .as("NO Job left behind by the rejected apply").isNull();
            assertThat(client.configMaps().inNamespace(NS)
                    .withName("hugmesh-image-spec-" + buildId).get())
                    .as("NO spec ConfigMap left behind by the rejected apply").isNull();
        }
    }
}
