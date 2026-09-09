package net.hugmesh.adminbff.testreports;

import io.fabric8.kubernetes.api.model.HasMetadata;
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
 * The REAL test-runner launcher: applies the rendered Job manifest to the cluster
 * with the fabric8 {@code KubernetesClient} (already on the classpath via the
 * spring-cloud-kubernetes leader starter). This is the piece the design says must be
 * BUILT — "reuse the backup orchestrator k8s-launch pattern but BUILD the real
 * launch since backup applyJob is a no-op".
 *
 * <p>Only wired (see {@link TestReportsConfig}) when {@code testreports.launch.enabled=true}
 * AND a usable in-cluster/kubeconfig context is present; otherwise the
 * {@link NoopJobLauncher} default is used so a cluster-less BFF still exercises the
 * full contract. The Job is created with the {@code test-runner} ServiceAccount
 * declared in the manifest (least-privilege RBAC in {@code jobs/test-runner-rbac.yaml}).
 *
 * <p>The {@code KubernetesClient} is supplied by a provider so the bean can be
 * constructed (and the seam signal published) even though the client itself is
 * created lazily on first apply — a transient API-server blip at startup must not
 * fail the BFF boot. Its acquire/apply/close lifecycle is expressed with
 * {@code Mono.usingWhen} (acquire lazily, apply, ALWAYS close — success, error, or
 * cancellation — mirroring what try-with-resources guaranteed), offloaded onto
 * {@code Schedulers.boundedElastic()} since the fabric8 client does blocking I/O; the
 * games {@code Fabric8InstanceConfigMapWriter} is the in-repo precedent.
 */
public class Fabric8JobLauncher implements JobLauncher {

    private static final Logger log = LoggerFactory.getLogger(Fabric8JobLauncher.class);

    /** Supplies a configured client; separated so it can be stubbed in tests. */
    @FunctionalInterface
    public interface ClientFactory {
        KubernetesClient get();
    }

    private final ClientFactory clientFactory;
    private final String namespace;

    public Fabric8JobLauncher(ClientFactory clientFactory, String namespace) {
        this.clientFactory = clientFactory;
        this.namespace = (namespace == null || namespace.isBlank()) ? "hugmesh-backend" : namespace;
    }

    @Override
    public Mono<String> apply(String manifest, String runId) {
        // Reactive resource lifecycle: Mono.usingWhen acquires the client LAZILY
        // (clientFactory::get), applies the manifest, and ALWAYS closes the client
        // afterwards — success, error, or cancellation — the same always-closes guarantee
        // try-with-resources gave, expressed reactively. subscribeOn(boundedElastic) keeps
        // both the acquire (a DNS lookup / API-server handshake) and the blocking apply off
        // whichever thread subscribes, so the offload is a property of the SEAM rather than
        // something each call site has to remember.
        return Mono.usingWhen(
                        Mono.fromCallable(() -> requireClient(clientFactory.get())),
                        client -> Mono.fromCallable(() -> applyBlocking(client, manifest, runId)),
                        client -> Mono.fromRunnable(client::close))
                .subscribeOn(Schedulers.boundedElastic())
                .onErrorMap(KubernetesClientException.class, e -> {
                    // A cluster-side rejection (RBAC, admission, conflict) is an operator-
                    // facing 502 — never a 500 that leaks a stack trace to the admin-ui.
                    log.warn("[test-reports] k8s apply for run {} failed: {}", runId, e.getMessage());
                    return ApiException.badGateway("could not launch test-runner Job: " + e.getMessage());
                })
                .onErrorMap(e -> !(e instanceof ApiException), e -> {
                    log.warn("[test-reports] k8s apply for run {} errored: {}", runId, e.toString());
                    return ApiException.badGateway("could not launch test-runner Job");
                });
    }

    /**
     * FAIL CLOSED on a null client. {@code Mono.usingWhen} treats an EMPTY resource publisher as
     * "no resource": the closure is never invoked and the whole Mono completes EMPTY — which
     * downstream reads as a SILENT SUCCESS (no error, no status update, no log). A
     * {@code ClientFactory} that returns null produces exactly that empty publisher via
     * {@code Mono.fromCallable}. The pre-reactive body NPE'd inside try-with-resources and
     * surfaced through the error mapping, so we reassert that contract explicitly here.
     */
    private static KubernetesClient requireClient(KubernetesClient client) {
        if (client == null) {
            throw new IllegalStateException("kubernetes client factory returned null");
        }
        return client;
    }

    /** The blocking fabric8 round-trip; the client's lifecycle is owned by {@link #apply}. */
    private String applyBlocking(KubernetesClient client, String manifest, String runId)
            throws java.io.IOException {
        try (var stream = new ByteArrayInputStream(manifest.getBytes(StandardCharsets.UTF_8))) {
            List<HasMetadata> applied = client.load(stream).inNamespace(namespace).create();
            String name = applied.stream()
                    .filter(r -> "Job".equals(r.getKind()))
                    .map(r -> r.getMetadata() == null ? null : r.getMetadata().getName())
                    .filter(n -> n != null)
                    .findFirst()
                    .orElse("hugmesh-test-runner-" + runId);
            log.info("[test-reports] applied test-runner Job '{}' (run {}) in namespace {}",
                    name, runId, namespace);
            return name;
        }
    }

    @Override
    public boolean isReal() {
        return true;
    }
}
