package net.hugmesh.adminbff.storage;

import io.fabric8.kubernetes.api.model.ConfigMapBuilder;
import io.fabric8.kubernetes.client.KubernetesClientException;
import io.fabric8.kubernetes.client.server.mock.EnableKubernetesMockClient;
import io.fabric8.kubernetes.client.server.mock.KubernetesMockServer;
import org.junit.jupiter.api.Test;
import reactor.test.StepVerifier;
import net.hugmesh.adminbff.support.RecordingKubernetesClient;
import net.hugmesh.adminbff.support.SubscribingThread;

import java.time.Duration;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The two load-bearing guarantees of the {@code Mono.usingWhen} rewrite of the node-storage
 * writer, asserted directly rather than inferred from a log line:
 * <ol>
 *   <li><b>the offload is real</b> — the client acquire AND the blocking server-side apply run
 *       on a {@code boundedElastic} thread, NOT on the thread that subscribed. This is the seam
 *       whose PRE-change body genuinely blocked a reactive thread:
 *       {@code NodeStorageReconciler.runOnce()} is
 *       {@code listActiveAll().concatMap(...).collectList().flatMap(this::renderAndReconcile)},
 *       so the old inline {@code writer.writeAssignments(elements)} ran client construction +
 *       DNS + HTTPS on the R2DBC thread that delivered {@code collectList()};</li>
 *   <li><b>the client is ALWAYS closed</b> — success and failure alike.</li>
 * </ol>
 *
 * <p>Plus the fail-closed contract for a {@code ClientFactory} that returns NULL: an empty
 * resource publisher makes {@code Mono.usingWhen} skip the closure and complete EMPTY, and the
 * reconciler's {@code flatMap} on the result would then be skipped entirely — no
 * {@code propagation_state} advance AND no failure mark, i.e. a tick that silently did nothing.
 * The writer must emit {@code false} (retry next tick) instead.
 */
@EnableKubernetesMockClient
class Fabric8NodeStorageConfigMapWriterLifecycleTest {

    private static final String NS = "devops";

    /** The exact request a server-side apply of the assignments ConfigMap issues. */
    private static final String SSA_PATH =
            "/api/v1/namespaces/devops/configmaps/node-storage-assignments?fieldManager=fabric8";

    /**
     * Injected by the fabric8 JUnit5 extension (fresh mock server per test). EXPECTATION mode,
     * not {@code crud = true}: the CRUD mock does not implement server-side apply, so the one
     * test that needs a SUCCESSFUL apply scripts the PATCH itself.
     */
    KubernetesMockServer server;

    private static List<StorageAssignmentElement> oneElement() {
        return List.of(new StorageAssignmentElement(
                "a-1", "owncast", "owncast-data", "pi-edge-01", "/mnt/pool-1",
                "hugmesh-backend", "4", "active"));
    }

    @Test
    void writeAssignments_movesAcquireAndApplyOffTheSubscribingThread() {
        AtomicReference<String> acquireThread = new AtomicReference<>();
        RecordingKubernetesClient recorder =
                RecordingKubernetesClient.failingWith(new KubernetesClientException("no cluster"));
        Fabric8NodeStorageConfigMapWriter writer = new Fabric8NodeStorageConfigMapWriter(() -> {
            acquireThread.set(Thread.currentThread().getName());
            return recorder.client();
        }, NS);

        AtomicReference<Boolean> ok = new AtomicReference<>();
        SubscribingThread.runExpectingSuccess(
                () -> ok.set(writer.writeAssignments(oneElement()).block()));

        // Swallowed to false (retry next tick) — never a crashed reconcile loop.
        assertThat(ok.get()).isFalse();
        assertThat(acquireThread.get())
                .as("client acquire (DNS + API-server handshake) must leave the reconciler's thread")
                .isNotEqualTo(SubscribingThread.NAME)
                .startsWith("boundedElastic-");
        assertThat(recorder.useThread.get())
                .as("the blocking server-side apply must leave the reconciler's thread")
                .isNotEqualTo(SubscribingThread.NAME)
                .startsWith("boundedElastic-");
    }

    @Test
    void writeAssignments_closesTheClient_whenTheApplyFails() {
        RecordingKubernetesClient recorder =
                RecordingKubernetesClient.failingWith(new KubernetesClientException("no cluster"));
        Fabric8NodeStorageConfigMapWriter writer =
                new Fabric8NodeStorageConfigMapWriter(recorder::client, NS);

        assertThat(writer.writeAssignments(oneElement()).block()).isFalse();

        assertThat(recorder.closeCount.get())
                .as("a leaked KubernetesClient leaks its OkHttp connection pool, once per tick")
                .isEqualTo(1);
    }

    @Test
    void writeAssignments_closesTheClient_onSuccess() {
        server.expect().patch().withPath(SSA_PATH)
                .andReturn(200, new ConfigMapBuilder().withNewMetadata()
                        .withName(Fabric8NodeStorageConfigMapWriter.CONFIGMAP_NAME)
                        .withNamespace(NS).endMetadata().build())
                .once();
        RecordingKubernetesClient recorder = RecordingKubernetesClient.delegatingTo(server.createClient());
        Fabric8NodeStorageConfigMapWriter writer =
                new Fabric8NodeStorageConfigMapWriter(recorder::client, NS);

        assertThat(writer.writeAssignments(oneElement()).block()).isTrue();

        assertThat(recorder.closeCount.get())
                .as("the completion arm of Mono.usingWhen must close the client too")
                .isEqualTo(1);
    }

    @Test
    void nullClientFactory_emitsFalse_neverCompletesEmpty() {
        Fabric8NodeStorageConfigMapWriter writer =
                new Fabric8NodeStorageConfigMapWriter(() -> null, NS);

        // An EMPTY completion here would make the reconciler skip BOTH the applied-mark and the
        // failed-mark for the tick; the contract is a single false emission.
        StepVerifier.create(writer.writeAssignments(oneElement()))
                .expectNext(Boolean.FALSE)
                .expectComplete()
                .verify(Duration.ofSeconds(30));
    }
}
