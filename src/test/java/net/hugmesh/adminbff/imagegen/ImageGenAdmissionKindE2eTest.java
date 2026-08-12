package net.hugmesh.adminbff.imagegen;

import io.fabric8.kubernetes.api.model.ConfigMap;
import io.fabric8.kubernetes.api.model.ConfigMapBuilder;
import io.fabric8.kubernetes.api.model.DeletionPropagation;
import io.fabric8.kubernetes.api.model.batch.v1.Job;
import io.fabric8.kubernetes.client.Config;
import io.fabric8.kubernetes.client.ConfigBuilder;
import io.fabric8.kubernetes.client.KubernetesClient;
import io.fabric8.kubernetes.client.KubernetesClientBuilder;
import io.fabric8.kubernetes.client.KubernetesClientException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import net.hugmesh.adminbff.sshterminal.ImageBuild;

import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * LIVE-CLUSTER e2e of the admission-layer {@code hugmesh-image-spec-} prefix pin
 * ({@code jobs/image-gen-admission.yaml}) — SHIPS DARK. Gated on
 * {@code IMAGEGEN_KIND_E2E_ADMISSION=true}, a SEPARATE gate from {@code IMAGEGEN_KIND_E2E}:
 * that one proves the spec channel on a cluster WITHOUT the policy, whereas this class
 * ADDITIONALLY requires {@code jobs/image-gen-admission.yaml} applied (its denial legs would
 * otherwise fail because the writes would be ALLOWED). A plain {@code ./mvnw test} run SKIPS
 * this class entirely (offline-safe, no kubeconfig touched).
 *
 * <p>Every "as admin-bff" call runs the ambient-kubeconfig client with IMPERSONATION of
 * {@code system:serviceaccount:hugmesh-backend:admin-bff}. The API server rewrites the
 * request's user context BEFORE admission, so the policy's
 * {@code request.userInfo.username} matchCondition sees exactly the same principal a real
 * pod-token-authenticated admin-bff would present — impersonation genuinely exercises the
 * pin. Legs proven when enabled:
 * <ol>
 *   <li>CREATE of {@code hugmesh-image-spec-<uuid>} as admin-bff is ALLOWED, and so is
 *       its (prefixed) DELETE — the launcher's rollback path survives the pin;</li>
 *   <li>CREATE of a non-prefixed ConfigMap as admin-bff is DENIED with the policy's
 *       message;</li>
 *   <li>generateName CREATEs are judged on the FINAL generated name — validating admission
 *       runs after the API server's registry generates it from {@code metadata.generateName}
 *       (only mutating admission sees the name-less object) — so a prefixed stem is ALLOWED
 *       (and the generated name is verified in-prefix) while a non-prefixed stem is
 *       DENIED;</li>
 *   <li>UPDATE (fabric8 {@code edit()} = API PATCH) of a non-prefixed EXISTING ConfigMap
 *       (created by the test as the ambient cluster-admin, cleaned up after) is DENIED;</li>
 *   <li>DELETE of that non-prefixed ConfigMap is DENIED — the co-tenant object survives
 *       untouched;</li>
 *   <li>the REAL spec-channel launcher path ({@link ImageBuildOrchestrator#renderManifest}
 *       + {@link Fabric8ImageJobLauncher}) still works end-to-end AS admin-bff under the
 *       policy, ownerReference patch (a prefixed UPDATE) included.</li>
 * </ol>
 *
 * <p>PREREQUISITES on the target cluster: namespace {@code hugmesh-backend} exists,
 * {@code jobs/image-gen-rbac.yaml} AND {@code jobs/image-gen-admission.yaml} are applied
 * (k8s ≥ 1.30 for the latter; the kind validation cluster runs ≥ 1.32), and the ambient
 * kubeconfig user can create/delete ConfigMaps there and impersonate the admin-bff SA
 * (kind's admin context is cluster-admin, so it can).
 *
 * <p>The {@code IMAGEGEN_KIND_E2E_IMAGE} / {@code IMAGEGEN_KIND_E2E_COMMAND} test-only
 * manifest overrides from {@link ImageGenKindE2eTest} apply here too (the launcher leg does
 * not assert pod success, so neither is required).
 */
@EnabledIfEnvironmentVariable(named = "IMAGEGEN_KIND_E2E_ADMISSION", matches = "true")
class ImageGenAdmissionKindE2eTest {

    private static final String NS = "hugmesh-backend";
    private static final String ADMIN_BFF_USER = "system:serviceaccount:" + NS + ":admin-bff";
    /** metadata.name of BOTH policy objects in jobs/image-gen-admission.yaml — the API
     *  server's denial status embeds it, which is what pins a failure to OUR policy (an
     *  RBAC denial would read "User ... cannot create resource", never this token). */
    private static final String POLICY_NAME = "hugmesh-image-spec-prefix-pin";
    /** Distinctive lead-in of the policy's message/messageExpression. */
    private static final String POLICY_MESSAGE = "image-spec prefix pin";

    private final ImageBuildOrchestrator renderer =
            new ImageBuildOrchestrator(null, new NoopImageJobLauncher(), 8);

    /** Ambient kubeconfig, impersonating the admin-bff SA (see class doc). */
    private static KubernetesClient adminBffClient() {
        Config cfg = new ConfigBuilder(Config.autoConfigure(null))
                .withImpersonateUsername(ADMIN_BFF_USER)
                .withImpersonateGroups("system:serviceaccounts", "system:authenticated")
                .build();
        return new KubernetesClientBuilder().withConfig(cfg).build();
    }

    private static ConfigMap cm(String name) {
        return new ConfigMapBuilder()
                .withNewMetadata().withName(name).withNamespace(NS)
                .addToLabels("e2e", "imagegen-admission-pin").endMetadata()
                .addToData("marker", "created by ImageGenAdmissionKindE2eTest")
                .build();
    }

    // ── ImageGenKindE2eTest's spec-build + test-only-override helpers (kept private
    //    there by design; duplicated rather than widening that class's surface) ──────────

    private static ImageBuild specBuild(String buildId) {
        return new ImageBuild(buildId, null, "e2e@kind", "brandx/alice", "brandx",
                ImageBuild.IMAGE_PRIMARY, "rpi5", null, ImageBuild.STATUS_QUEUED, true,
                null, null, null, null, null, null,
                "{\"role\":\"gateway\",\"platform\":\"rpi5\",\"hostname\":\"e2e\"}");
    }

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

    // ── leg 1: prefixed writes still ALLOWED ────────────────────────────────────────────

    @Test
    void prefixedCreateAndDelete_asAdminBff_allowedUnderPolicy() {
        String name = "hugmesh-image-spec-" + UUID.randomUUID();
        try (KubernetesClient bff = adminBffClient()) {
            ConfigMap created = bff.resource(cm(name)).create();
            assertThat(created).as("prefixed create passes the pin").isNotNull();
            assertThat(created.getMetadata().getUid()).isNotBlank();

            // The launcher's ROLLBACK path is a prefixed delete — must also pass the pin.
            bff.configMaps().inNamespace(NS).withName(name).delete();
            assertThat(bff.configMaps().inNamespace(NS).withName(name).get())
                    .as("prefixed delete passes the pin (rollback path)").isNull();
        } finally {
            // Belt-and-braces cleanup as the ambient user so a failed assertion never
            // litters the cluster.
            try (KubernetesClient admin = new KubernetesClientBuilder().build()) {
                admin.configMaps().inNamespace(NS).withName(name).delete();
            } catch (Exception ignored) { /* already gone */ }
        }
    }

    // ── leg 2: non-prefixed CREATE (explicit name) denied ───────────────────────────────

    @Test
    void nonPrefixedCreate_asAdminBff_denied() {
        String name = "imagegen-admission-e2e-" + UUID.randomUUID();
        try (KubernetesClient bff = adminBffClient()) {
            assertThatThrownBy(() -> bff.resource(cm(name)).create())
                    .as("non-prefixed create is denied BY THE POLICY")
                    .isInstanceOf(KubernetesClientException.class)
                    .hasMessageContaining(POLICY_NAME)
                    .hasMessageContaining(POLICY_MESSAGE);
        }
        try (KubernetesClient admin = new KubernetesClientBuilder().build()) {
            assertThat(admin.configMaps().inNamespace(NS).withName(name).get())
                    .as("denied create left nothing behind").isNull();
        }
    }

    // ── leg 3: generateName — the pin judges the FINAL generated name ───────────────────

    /**
     * VALIDATING admission runs inside the registry's create path AFTER the server has
     * generated the final name from {@code metadata.generateName} (only MUTATING admission
     * sees the name-less object), so the policy evaluates the real {@code <stem>xxxxx} name
     * that would be stored: a prefixed stem passes the pin, a non-prefixed stem fails it.
     * The policy's empty-name clause is defense-in-depth and is NOT expected to fire here.
     */
    @Test
    void generateNameCreate_asAdminBff_judgedOnFinalGeneratedName() {
        String createdName = null;
        try (KubernetesClient bff = adminBffClient()) {
            // Prefixed stem → the server-generated name starts with the prefix → ALLOWED.
            ConfigMap prefixed = new ConfigMapBuilder()
                    .withNewMetadata().withGenerateName("hugmesh-image-spec-")
                    .withNamespace(NS)
                    .addToLabels("e2e", "imagegen-admission-pin").endMetadata()
                    .addToData("marker", "created by ImageGenAdmissionKindE2eTest")
                    .build();
            ConfigMap created = bff.resource(prefixed).create();
            createdName = created.getMetadata().getName();
            assertThat(createdName)
                    .as("generated name carries the stem, so the create passes the pin")
                    .startsWith("hugmesh-image-spec-");

            // Non-prefixed stem → the generated name lacks the prefix → DENIED.
            ConfigMap nonPrefixed = new ConfigMapBuilder()
                    .withNewMetadata().withGenerateName("imagegen-admission-e2e-")
                    .withNamespace(NS).endMetadata()
                    .build();
            assertThatThrownBy(() -> bff.resource(nonPrefixed).create())
                    .as("non-prefixed generateName resolves to a non-prefixed final name"
                            + " and is denied BY THE POLICY")
                    .isInstanceOf(KubernetesClientException.class)
                    .hasMessageContaining(POLICY_NAME)
                    .hasMessageContaining(POLICY_MESSAGE);

            // The allowed object is in-prefix, so admin-bff's own delete passes the pin
            // (and proves the generated name is a perfectly ordinary prefixed target).
            bff.configMaps().inNamespace(NS).withName(createdName).delete();
            assertThat(bff.configMaps().inNamespace(NS).withName(createdName).get())
                    .as("generated-name ConfigMap cleaned up as admin-bff").isNull();
        } finally {
            // Belt-and-braces cleanup as the ambient user — the generated name is captured
            // from the create response, so a failed assertion never litters the cluster.
            if (createdName != null) {
                try (KubernetesClient admin = new KubernetesClientBuilder().build()) {
                    admin.configMaps().inNamespace(NS).withName(createdName).delete();
                } catch (Exception ignored) { /* already gone */ }
            }
        }
    }

    // ── legs 4+5: non-prefixed EXISTING ConfigMap — UPDATE and DELETE denied ────────────

    @Test
    void nonPrefixedExisting_patchAndDelete_asAdminBff_denied() {
        String name = "imagegen-admission-e2e-cotenant-" + UUID.randomUUID();
        try (KubernetesClient admin = new KubernetesClientBuilder().build()) {
            // The "co-tenant" fixture, created by the ambient cluster-admin — the policy's
            // matchCondition scopes to admin-bff only, so this create is untouched by it.
            admin.resource(cm(name)).create();
            try (KubernetesClient bff = adminBffClient()) {
                // fabric8 edit() = GET (allowed by RBAC) + PATCH; the PATCH surfaces as
                // UPDATE in admission and must be denied.
                assertThatThrownBy(() -> bff.configMaps().inNamespace(NS).withName(name)
                        .edit(c -> new ConfigMapBuilder(c)
                                .addToData("pwned", "true").build()))
                        .as("patch of a co-tenant ConfigMap is denied")
                        .isInstanceOf(KubernetesClientException.class)
                        .hasMessageContaining(POLICY_NAME)
                        .hasMessageContaining(POLICY_MESSAGE);

                assertThatThrownBy(() -> bff.configMaps().inNamespace(NS).withName(name)
                        .delete())
                        .as("delete of a co-tenant ConfigMap is denied (the DEFANGED"
                                + " rollback verb)")
                        .isInstanceOf(KubernetesClientException.class)
                        .hasMessageContaining(POLICY_NAME)
                        .hasMessageContaining(POLICY_MESSAGE);
            }
            ConfigMap survivor = admin.configMaps().inNamespace(NS).withName(name).get();
            assertThat(survivor).as("co-tenant ConfigMap survives untouched").isNotNull();
            assertThat(survivor.getData()).doesNotContainKey("pwned");
        } finally {
            try (KubernetesClient admin = new KubernetesClientBuilder().build()) {
                admin.configMaps().inNamespace(NS).withName(name).delete();
            } catch (Exception ignored) { /* already gone */ }
        }
    }

    // ── leg 6: the REAL launcher path, AS admin-bff, under the policy ───────────────────

    @Test
    void specChannelLauncher_asAdminBff_worksEndToEndUnderPolicy() {
        String buildId = UUID.randomUUID().toString();
        String cmName = "hugmesh-image-spec-" + buildId;
        String manifest = applyTestOnlyOverrides(renderer.renderManifest(specBuild(buildId)));

        // The launcher itself runs AS admin-bff: ConfigMap create, Job create and the
        // best-effort ownerReference patch all pass through the pin.
        Fabric8ImageJobLauncher launcher = new Fabric8ImageJobLauncher(
                ImageGenAdmissionKindE2eTest::adminBffClient, NS);
        String jobName = launcher.apply(manifest, buildId);

        try (KubernetesClient admin = new KubernetesClientBuilder().build()) {
            try {
                Job job = admin.batch().v1().jobs().inNamespace(NS).withName(jobName).get();
                assertThat(job).as("Job exists after apply under the policy").isNotNull();

                ConfigMap cm = admin.configMaps().inNamespace(NS).withName(cmName).get();
                assertThat(cm).as("spec ConfigMap exists after apply under the policy")
                        .isNotNull();
                assertThat(cm.getData()).containsKey("spec.json");
                // The ownerReference patch is a PREFIXED UPDATE by admin-bff — its presence
                // proves the pin let the launcher's third call through as well (were it
                // denied, the launcher logs + proceeds, and this assertion catches it).
                assertThat(cm.getMetadata().getOwnerReferences())
                        .as("ownerReference patch passed the pin").hasSize(1);
                assertThat(cm.getMetadata().getOwnerReferences().get(0).getName())
                        .isEqualTo(jobName);
            } finally {
                // Cleanup: reap the Job (background cascade GCs the ConfigMap via the
                // ownerRef) plus an explicit best-effort ConfigMap delete.
                try {
                    admin.batch().v1().jobs().inNamespace(NS).withName(jobName)
                            .withPropagationPolicy(DeletionPropagation.BACKGROUND).delete();
                } catch (Exception ignored) { /* already gone */ }
                try {
                    admin.configMaps().inNamespace(NS).withName(cmName).delete();
                } catch (Exception ignored) { /* already gone */ }
            }
        }
    }
}
