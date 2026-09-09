package net.hugmesh.adminbff.testreports;

import io.fabric8.kubernetes.client.KubernetesClient;
import io.fabric8.kubernetes.client.KubernetesClientException;
import io.fabric8.kubernetes.client.server.mock.EnableKubernetesMockClient;
import io.fabric8.kubernetes.client.server.mock.KubernetesMockServer;
import org.junit.jupiter.api.Test;
import reactor.test.StepVerifier;
import net.hugmesh.adminbff.support.RecordingKubernetesClient;
import net.hugmesh.adminbff.support.SubscribingThread;
import net.hugmesh.commons.web.ApiException;

import java.time.Duration;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * The two load-bearing guarantees of the {@code Mono.usingWhen} rewrite of this seam, each
 * asserted directly rather than inferred from a log line:
 * <ol>
 *   <li><b>the offload is real</b> — the client acquire AND the blocking fabric8 round-trip run
 *       on a {@code boundedElastic} thread, NOT on the thread that subscribed (in production
 *       that thread is an R2DBC/Netty event loop, since {@code TestReportsService} composes
 *       {@code repo.insert(...).flatMap(run -> orchestrator.launch(run)...)});</li>
 *   <li><b>the client is ALWAYS closed</b> — on success and on failure alike. That was
 *       structural under try-with-resources; under {@code Mono.usingWhen} it is only true if
 *       the cleanup arm is genuinely wired, so it needs a test.</li>
 * </ol>
 *
 * <p>Plus the fail-closed contract for a {@code ClientFactory} that returns NULL:
 * {@code Mono.usingWhen} treats an empty resource publisher as "no resource" and completes
 * EMPTY, which downstream would read as a silent success (no error, no status update, no log).
 * The seam must raise the same 502 the pre-reactive NPE produced.
 */
@EnableKubernetesMockClient(crud = true)
class Fabric8JobLauncherLifecycleTest {

    private static final String NS = "hugmesh-backend";

    /** Injected by the fabric8 JUnit5 extension (fresh CRUD mock server per test). */
    KubernetesMockServer server;
    KubernetesClient client;

    private static final String JOB_MANIFEST = """
            apiVersion: batch/v1
            kind: Job
            metadata:
              name: hugmesh-test-runner-run-1
              namespace: hugmesh-backend
            spec:
              template:
                spec:
                  restartPolicy: Never
                  containers:
                    - name: runner
                      image: busybox:1.36
            """;

    @Test
    void apply_movesAcquireAndApplyOffTheSubscribingThread() {
        AtomicReference<String> acquireThread = new AtomicReference<>();
        RecordingKubernetesClient recorder = RecordingKubernetesClient.delegatingTo(server.createClient());
        Fabric8JobLauncher launcher = new Fabric8JobLauncher(() -> {
            acquireThread.set(Thread.currentThread().getName());
            return recorder.client();
        }, NS);

        AtomicReference<String> jobName = new AtomicReference<>();
        SubscribingThread.runExpectingSuccess(
                () -> jobName.set(launcher.apply(JOB_MANIFEST, "run-1").block()));

        assertThat(jobName.get()).isEqualTo("hugmesh-test-runner-run-1");
        assertThat(acquireThread.get())
                .as("client acquire (DNS + API-server handshake) must leave the subscribing thread")
                .isNotEqualTo(SubscribingThread.NAME)
                .startsWith("boundedElastic-");
        assertThat(recorder.useThread.get())
                .as("the blocking fabric8 round-trip must leave the subscribing thread")
                .isNotEqualTo(SubscribingThread.NAME)
                .startsWith("boundedElastic-");
    }

    @Test
    void apply_closesTheClient_onSuccess() {
        RecordingKubernetesClient recorder = RecordingKubernetesClient.delegatingTo(server.createClient());
        Fabric8JobLauncher launcher = new Fabric8JobLauncher(recorder::client, NS);

        assertThat(launcher.apply(JOB_MANIFEST, "run-1").block())
                .isEqualTo("hugmesh-test-runner-run-1");

        assertThat(recorder.closeCount.get())
                .as("a leaked KubernetesClient leaks its OkHttp connection pool, once per launch")
                .isEqualTo(1);
    }

    @Test
    void apply_closesTheClient_whenTheApplyFails() {
        RecordingKubernetesClient recorder =
                RecordingKubernetesClient.failingWith(new KubernetesClientException("forbidden: jobs"));
        Fabric8JobLauncher launcher = new Fabric8JobLauncher(recorder::client, NS);

        assertThatThrownBy(() -> launcher.apply(JOB_MANIFEST, "run-1").block())
                .isInstanceOf(ApiException.class);

        assertThat(recorder.closeCount.get())
                .as("the error arm of Mono.usingWhen must close the client too")
                .isEqualTo(1);
    }

    @Test
    void nullClientFactory_failsClosedWith502_neverCompletesEmpty() {
        Fabric8JobLauncher launcher = new Fabric8JobLauncher(() -> null, NS);

        StepVerifier.create(launcher.apply(JOB_MANIFEST, "run-1"))
                .expectErrorSatisfies(e -> {
                    assertThat(e).isInstanceOf(ApiException.class);
                    assertThat(((ApiException) e).status().value()).isEqualTo(502);
                })
                .verify(Duration.ofSeconds(30));
    }
}
