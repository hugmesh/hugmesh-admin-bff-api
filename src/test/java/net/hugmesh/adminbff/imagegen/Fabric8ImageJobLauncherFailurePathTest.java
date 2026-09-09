package net.hugmesh.adminbff.imagegen;

import io.fabric8.kubernetes.api.model.ConfigMapBuilder;
import io.fabric8.kubernetes.api.model.StatusBuilder;
import io.fabric8.kubernetes.api.model.batch.v1.JobBuilder;
import io.fabric8.kubernetes.client.server.mock.EnableKubernetesMockClient;
import io.fabric8.kubernetes.client.server.mock.KubernetesMockServer;
import io.fabric8.mockwebserver.http.RecordedRequest;
import org.junit.jupiter.api.Test;
import net.hugmesh.adminbff.sshterminal.ImageBuild;
import net.hugmesh.commons.web.ApiException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * PARTIAL-FAILURE ATOMICITY of the two-doc spec-channel apply, pinned request-by-request
 * against the fabric8 mock server in EXPECTATION mode (every API call is scripted, so the
 * exact call sequence is asserted — not just the end state):
 * <ul>
 *   <li>ConfigMap create REJECTED (e.g. the RBAC grant missing) → the apply fails with the
 *       operator-facing 502 {@link ApiException} and the Job create is NEVER attempted — a
 *       spec build can never silently degrade to a legacy run;</li>
 *   <li>Job create REJECTED after the ConfigMap create succeeded → the launcher best-effort
 *       DELETEs the just-created ConfigMap (the ownerRef reap never got wired) before the
 *       502 propagates — no leaked ConfigMap;</li>
 *   <li>ownerReference patch failure AFTER the Job exists → logged and swallowed; the apply
 *       still returns the Job name (the build is already running — cleanup wiring must not
 *       kill it).</li>
 * </ul>
 *
 * <p>Background (verified against kubernetes-client 7.4.1 sources): fabric8's multi-doc
 * {@code load().create()} maps {@code Resource::create} over a sequential stream in parsed
 * document order and aborts on the first failure, but that ordering is an implementation
 * detail (undocumented) and nothing is ever rolled back — which is why
 * {@link Fabric8ImageJobLauncher} drives the two creates itself.
 */
@EnableKubernetesMockClient
class Fabric8ImageJobLauncherFailurePathTest {

    private static final String NS = "hugmesh-backend";
    private static final String BUILD_ID = "00000000-0000-0000-0000-000000000042";
    private static final String CM_NAME = "hugmesh-image-spec-" + BUILD_ID;
    private static final String JOB_NAME = "hugmesh-image-gen-" + BUILD_ID;
    private static final String CM_PATH = "/api/v1/namespaces/" + NS + "/configmaps";
    private static final String JOB_PATH = "/apis/batch/v1/namespaces/" + NS + "/jobs";

    // Injected by the fabric8 JUnit5 extension (fresh mock server per test, expectation mode).
    KubernetesMockServer server;

    private final ImageBuildOrchestrator renderer =
            new ImageBuildOrchestrator(null, new NoopImageJobLauncher(), 8);

    private String specManifest() {
        return renderer.renderManifest(new ImageBuild(BUILD_ID, null, "admin@x", "brandx/alice",
                "brandx", ImageBuild.IMAGE_PRIMARY, "rpi5", null, ImageBuild.STATUS_QUEUED, true,
                null, null, null, null, null, null,
                "{\"role\":\"gateway\",\"platform\":\"rpi5\"}"));
    }

    private Fabric8ImageJobLauncher launcher() {
        return new Fabric8ImageJobLauncher(() -> server.createClient(), NS);
    }

    @Test
    void configMapCreateRejected_surfaces502_andNeverCreatesTheJob() throws InterruptedException {
        server.expect().post().withPath(CM_PATH)
                .andReturn(403, new StatusBuilder().withCode(403)
                        .withMessage("configmaps is forbidden: no RBAC grant").build())
                .once();
        // NO expectation for the Job POST: were it attempted, the mock would answer 404 and
        // the request would still be recorded — the count/path assertions below catch it.

        assertThatThrownBy(() -> launcher().apply(specManifest(), BUILD_ID).block())
                .isInstanceOf(ApiException.class)
                .satisfies(e -> assertThat(((ApiException) e).status().value()).isEqualTo(502))
                .hasMessageContaining("could not launch image-gen Job");

        assertThat(server.getRequestCount())
                .as("exactly ONE api call: the rejected ConfigMap create").isEqualTo(1);
        RecordedRequest only = server.takeRequest();
        assertThat(only.getMethod()).isEqualTo("POST");
        assertThat(only.getPath()).isEqualTo(CM_PATH);
    }

    @Test
    void jobCreateRejected_rollsBackTheJustCreatedConfigMap_andSurfaces502() throws InterruptedException {
        server.expect().post().withPath(CM_PATH)
                .andReturn(201, new ConfigMapBuilder().withNewMetadata()
                        .withName(CM_NAME).withNamespace(NS).endMetadata().build())
                .once();
        server.expect().post().withPath(JOB_PATH)
                .andReturn(403, new StatusBuilder().withCode(403)
                        .withMessage("jobs is forbidden").build())
                .once();
        server.expect().delete().withPath(CM_PATH + "/" + CM_NAME)
                .andReturn(200, new StatusBuilder().withCode(200).build())
                .once();

        assertThatThrownBy(() -> launcher().apply(specManifest(), BUILD_ID).block())
                .isInstanceOf(ApiException.class)
                .satisfies(e -> assertThat(((ApiException) e).status().value()).isEqualTo(502));

        // Exact sequence: ConfigMap POST → Job POST (rejected) → rollback ConfigMap DELETE.
        assertThat(server.getRequestCount()).isEqualTo(3);
        RecordedRequest first = server.takeRequest();
        assertThat(first.getMethod()).isEqualTo("POST");
        assertThat(first.getPath()).isEqualTo(CM_PATH);
        RecordedRequest second = server.takeRequest();
        assertThat(second.getMethod()).isEqualTo("POST");
        assertThat(second.getPath()).isEqualTo(JOB_PATH);
        RecordedRequest third = server.takeRequest();
        assertThat(third.getMethod()).isEqualTo("DELETE");
        assertThat(third.getPath()).isEqualTo(CM_PATH + "/" + CM_NAME);
    }

    @Test
    void ownerRefPatchFailure_isBestEffort_applyStillSucceeds() {
        server.expect().post().withPath(CM_PATH)
                .andReturn(201, new ConfigMapBuilder().withNewMetadata()
                        .withName(CM_NAME).withNamespace(NS).endMetadata().build())
                .once();
        server.expect().post().withPath(JOB_PATH)
                .andReturn(201, new JobBuilder().withNewMetadata()
                        .withName(JOB_NAME).withNamespace(NS).withUid("uid-42").endMetadata().build())
                .once();
        // The ownerRef edit() starts with a GET of the ConfigMap — fail it (404: e.g. an
        // eager operator reaped the CM; NOT a 5xx, which fabric8 would retry ~20s): the
        // patch must be swallowed (warn log), NEVER kill the already-running build.
        server.expect().get().withPath(CM_PATH + "/" + CM_NAME)
                .andReturn(404, new StatusBuilder().withCode(404)
                        .withMessage("configmap gone").build())
                .always();

        assertThat(launcher().apply(specManifest(), BUILD_ID).block()).isEqualTo(JOB_NAME);
    }
}
