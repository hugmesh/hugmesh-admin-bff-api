package systems.hugmesh.adminbff.testreports;

import io.fabric8.kubernetes.api.model.HasMetadata;
import io.fabric8.kubernetes.client.KubernetesClient;
import io.fabric8.kubernetes.client.KubernetesClientException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import systems.hugmesh.commons.web.ApiException;

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
 * fail the BFF boot.
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
    public String apply(String manifest, String runId) {
        // TODO reactive: consider Mono.usingWhen(Mono.fromCallable(clientFactory::get), ...) for the KubernetesClient lifecycle
        try (KubernetesClient client = clientFactory.get();
             var stream = new ByteArrayInputStream(manifest.getBytes(StandardCharsets.UTF_8))) {
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
        } catch (KubernetesClientException e) {
            // A cluster-side rejection (RBAC, admission, conflict) is an operator-
            // facing 502 — never a 500 that leaks a stack trace to the admin-ui.
            log.warn("[test-reports] k8s apply for run {} failed: {}", runId, e.getMessage());
            throw ApiException.badGateway("could not launch test-runner Job: " + e.getMessage());
        } catch (Exception e) {
            log.warn("[test-reports] k8s apply for run {} errored: {}", runId, e.toString());
            throw ApiException.badGateway("could not launch test-runner Job");
        }
    }

    @Override
    public boolean isReal() {
        return true;
    }
}
