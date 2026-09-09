package net.hugmesh.adminbff.imagegen;

import io.fabric8.kubernetes.client.KubernetesClient;
import io.fabric8.kubernetes.client.KubernetesClientException;
import io.fabric8.kubernetes.client.server.mock.EnableKubernetesMockClient;
import io.fabric8.kubernetes.client.server.mock.KubernetesMockServer;
import org.junit.jupiter.api.Test;
import reactor.test.StepVerifier;
import net.hugmesh.adminbff.sshterminal.ImageBuild;
import net.hugmesh.adminbff.support.RecordingKubernetesClient;
import net.hugmesh.adminbff.support.SubscribingThread;
import net.hugmesh.commons.web.ApiException;

import java.time.Duration;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * The two load-bearing guarantees of the {@code Mono.usingWhen} rewrite of the image-gen seam,
 * asserted directly rather than inferred from a log line:
 * <ol>
 *   <li><b>the offload is real</b> — the client acquire AND the blocking three-step apply run on
 *       a {@code boundedElastic} thread, NOT on the thread that subscribed (in production that
 *       is an R2DBC/Netty event loop: {@code ImageBuildService} composes
 *       {@code builds.insert(queued).flatMap(b -> orchestrator.launch(b)...)});</li>
 *   <li><b>the client is ALWAYS closed</b> — success and failure alike, the guarantee
 *       try-with-resources used to give structurally.</li>
 * </ol>
 *
 * <p>Plus the fail-closed contract for a {@code ClientFactory} that returns NULL: an empty
 * resource publisher makes {@code Mono.usingWhen} skip the closure and complete EMPTY, which
 * {@link ImageBuildOrchestrator#launch} would read as success — the build row would stay QUEUED
 * with no STATUS_ERROR, no {@code failed} SSE event and no log. The seam must raise the 502 the
 * pre-reactive NPE produced.
 *
 * <p>Ordering / rollback of the two-doc apply is pinned separately by
 * {@link Fabric8ImageJobLauncherFailurePathTest}; the applied bytes by
 * {@link Fabric8ImageJobLauncherMockServerTest}. This class only covers the client LIFECYCLE.
 */
@EnableKubernetesMockClient(crud = true)
class Fabric8ImageJobLauncherLifecycleTest {

    private static final String NS = "hugmesh-backend";
    private static final String BUILD_ID = "00000000-0000-0000-0000-000000000042";
    private static final String JOB_NAME = "hugmesh-image-gen-" + BUILD_ID;

    /** Injected by the fabric8 JUnit5 extension (fresh CRUD mock server per test). */
    KubernetesMockServer server;
    KubernetesClient client;

    /** renderManifest never touches the repo, so a null repo is fine (render-only use). */
    private final ImageBuildOrchestrator renderer =
            new ImageBuildOrchestrator(null, new NoopImageJobLauncher(), 8);

    /** A LEGACY (no spec) build: a single Job document, so this test isolates the lifecycle. */
    private String legacyManifest() {
        return renderer.renderManifest(new ImageBuild(BUILD_ID, null, "admin@x", "brandx/alice",
                "brandx", ImageBuild.IMAGE_PRIMARY, "rpi5", null, ImageBuild.STATUS_QUEUED, true,
                null, null, null, null, null, null, null));
    }

    @Test
    void apply_movesAcquireAndApplyOffTheSubscribingThread() {
        AtomicReference<String> acquireThread = new AtomicReference<>();
        RecordingKubernetesClient recorder = RecordingKubernetesClient.delegatingTo(server.createClient());
        Fabric8ImageJobLauncher launcher = new Fabric8ImageJobLauncher(() -> {
            acquireThread.set(Thread.currentThread().getName());
            return recorder.client();
        }, NS);
        String manifest = legacyManifest();

        AtomicReference<String> jobName = new AtomicReference<>();
        SubscribingThread.runExpectingSuccess(
                () -> jobName.set(launcher.apply(manifest, BUILD_ID).block()));

        assertThat(jobName.get()).isEqualTo(JOB_NAME);
        assertThat(acquireThread.get())
                .as("client acquire (DNS + API-server handshake) must leave the subscribing thread")
                .isNotEqualTo(SubscribingThread.NAME)
                .startsWith("boundedElastic-");
        assertThat(recorder.useThread.get())
                .as("the blocking three-step apply must leave the subscribing thread")
                .isNotEqualTo(SubscribingThread.NAME)
                .startsWith("boundedElastic-");
    }

    @Test
    void apply_closesTheClient_onSuccess() {
        RecordingKubernetesClient recorder = RecordingKubernetesClient.delegatingTo(server.createClient());
        Fabric8ImageJobLauncher launcher = new Fabric8ImageJobLauncher(recorder::client, NS);

        assertThat(launcher.apply(legacyManifest(), BUILD_ID).block()).isEqualTo(JOB_NAME);

        assertThat(recorder.closeCount.get())
                .as("a leaked KubernetesClient leaks its OkHttp connection pool, once per launch")
                .isEqualTo(1);
    }

    @Test
    void apply_closesTheClient_whenTheApplyFails() {
        RecordingKubernetesClient recorder =
                RecordingKubernetesClient.failingWith(new KubernetesClientException("forbidden: jobs"));
        Fabric8ImageJobLauncher launcher = new Fabric8ImageJobLauncher(recorder::client, NS);

        assertThatThrownBy(() -> launcher.apply(legacyManifest(), BUILD_ID).block())
                .isInstanceOf(ApiException.class);

        assertThat(recorder.closeCount.get())
                .as("the error arm of Mono.usingWhen must close the client too")
                .isEqualTo(1);
    }

    @Test
    void nullClientFactory_failsClosedWith502_neverCompletesEmpty() {
        Fabric8ImageJobLauncher launcher = new Fabric8ImageJobLauncher(() -> null, NS);

        StepVerifier.create(launcher.apply(legacyManifest(), BUILD_ID))
                .expectErrorSatisfies(e -> {
                    assertThat(e).isInstanceOf(ApiException.class);
                    assertThat(((ApiException) e).status().value()).isEqualTo(502);
                })
                .verify(Duration.ofSeconds(30));
    }
}
