package systems.hugmesh.adminbff.platform;

import io.fabric8.kubernetes.api.model.Node;
import io.fabric8.kubernetes.client.KubernetesClient;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * The REAL platform-capability probe: discovers the foundational-infra presence by READING the
 * in-cluster Kubernetes API with the fabric8 {@link KubernetesClient} (already on the classpath
 * via the spring-cloud-kubernetes leader starter). Wired ONLY when
 * {@code app.platform-capabilities.k8s.enabled=true} (see {@link PlatformCapabilitiesConfig});
 * otherwise the {@link NoopPlatformCapabilityProbe} default is used.
 *
 * <h2>Read-only + fail-safe contract</h2>
 * <p>Every call here is a LIST / GET — NEVER a create/patch/delete. The three primitive reads are
 * delegated to the {@link K8sReader} seam (so the fail-safe composition is unit-testable without
 * the heavily-generic fabric8 fluent DSL). Each primitive returns a {@code Boolean} that is
 * {@code null} on ANY error (no client, API-server unreachable, RBAC-denied, parse error). The
 * composition treats {@code null} as "could-not-detect" → capability {@code false} + a warning;
 * a clean {@code false} (read succeeded, infra absent) is the truthful answer and is NOT warned.
 * The probe therefore NEVER throws and NEVER returns a faked {@code true} — an absent/denied
 * capability is reported absent, the safe direction (the UI degrades; the BFF stays authoritative).
 *
 * <h2>What each probe keys on</h2>
 * <ul>
 *   <li><b>argocdPresent</b> — the {@code applications.argoproj.io} CustomResourceDefinition is
 *       installed, OR an {@code argocd-server} Deployment exists in the {@code argocd} namespace.</li>
 *   <li><b>veleroPresent</b> — the {@code backups.velero.io} CustomResourceDefinition is installed,
 *       OR a {@code velero} Deployment exists in the {@code velero} namespace.</li>
 *   <li><b>buildNodePresent</b> — at least one Node carries the x86/amd64 build-node label
 *       {@value #BUILD_NODE_LABEL}{@code =true} AND advertises {@code kubernetes.io/arch=amd64}
 *       (the arch check guards against the label being mistakenly set on a Pi).</li>
 * </ul>
 *
 * <p>The {@code KubernetesClient} is supplied LAZILY (a {@link ClientFactory}, same as
 * {@code Fabric8JobLauncher}) so the bean constructs — and the probe answers — even if the
 * API-server is briefly unreachable at boot. A fresh client is built per probe cycle and closed.
 */
public class Fabric8PlatformCapabilityProbe implements PlatformCapabilityProbe {

    private static final Logger log = LoggerFactory.getLogger(Fabric8PlatformCapabilityProbe.class);

    /** The x86 build-stick node label the generator stamps (documented in MEMORY: x86 binhost). */
    static final String BUILD_NODE_LABEL = "hugmesh.systems/build-node";
    /** The standard well-known arch label, to confirm the build node is genuinely amd64/x86. */
    static final String ARCH_LABEL = "kubernetes.io/arch";

    static final String ARGOCD_CRD = "applications.argoproj.io";
    static final String ARGOCD_NAMESPACE = "argocd";
    static final String ARGOCD_DEPLOYMENT = "argocd-server";

    static final String VELERO_CRD = "backups.velero.io";
    static final String VELERO_NAMESPACE = "velero";
    static final String VELERO_DEPLOYMENT = "velero";

    /** Supplies a configured client; separated so it can be stubbed in tests. */
    @FunctionalInterface
    public interface ClientFactory {
        KubernetesClient get();
    }

    /**
     * The three READ-ONLY k8s primitives, each returning {@code Boolean}: {@code TRUE} present,
     * {@code FALSE} absent, {@code null} on error/denied. Extracted as a seam so the fail-safe
     * composition is unit-testable without mocking the generic fabric8 fluent DSL.
     * {@link Fabric8K8sReader} is the production implementation.
     */
    interface K8sReader {
        Boolean crdInstalled(String crdName);

        Boolean deploymentPresent(String namespace, String name);

        /** All Node label-maps (read-only); throws on a k8s error so the caller can fail-safe. */
        List<Map<String, String>> nodeLabels();
    }

    private final ClientFactory clientFactory;

    public Fabric8PlatformCapabilityProbe(ClientFactory clientFactory) {
        this.clientFactory = clientFactory;
    }

    @Override
    public boolean isReal() {
        return true;
    }

    @Override
    public Result probe() {
        List<String> warnings = new ArrayList<>();
        KubernetesClient client;
        try {
            client = clientFactory.get();
        } catch (Exception e) {
            log.warn("[platform-capabilities] could not build k8s client: {}", e.toString());
            // Fixed message — do NOT echo the exception text (it can leak kubeconfig host / path
            // detail); matches the fixed copy on the other denial paths below.
            warnings.add("Kubernetes client unavailable; ArgoCD / Velero / build-node presence "
                    + "could not be detected and are reported absent.");
            return new Result(false, false, false, warnings);
        }
        try {
            return probe(new Fabric8K8sReader(client), warnings);
        } finally {
            try {
                client.close();
            } catch (Exception ignore) { //NOPMD EmptyCatchBlock - best-effort close on client
            }
        }
    }

    /** The fail-safe composition over the {@link K8sReader} seam — the unit-tested core. */
    Result probe(K8sReader reader, List<String> warnings) {
        boolean argocd = crdOrDeploymentPresent(reader, "ArgoCD", ARGOCD_CRD,
                ARGOCD_NAMESPACE, ARGOCD_DEPLOYMENT, warnings);
        boolean velero = crdOrDeploymentPresent(reader, "Velero", VELERO_CRD,
                VELERO_NAMESPACE, VELERO_DEPLOYMENT, warnings);
        boolean buildNode = buildNodePresent(reader, warnings);
        return new Result(argocd, velero, buildNode, warnings);
    }

    /**
     * Capability present iff the named CRD is installed OR the named Deployment exists in the
     * named namespace. Each lookup is independently fail-safe — a denial/error on the CRD read
     * still lets the Deployment read decide, and a failure of BOTH yields {@code false} + warning.
     */
    private boolean crdOrDeploymentPresent(K8sReader reader, String label, String crdName,
                                           String namespace, String deployment, List<String> warnings) {
        Boolean crd = reader.crdInstalled(crdName);
        if (Boolean.TRUE.equals(crd)) {
            return true;
        }
        Boolean dep = reader.deploymentPresent(namespace, deployment);
        if (Boolean.TRUE.equals(dep)) {
            return true;
        }
        // Only warn when BOTH reads errored (null) — a clean "absent" (false) is not a warning,
        // it is the truthful answer that the infra is simply not installed.
        if (crd == null && dep == null) {
            warnings.add(label + " presence could not be detected (Kubernetes read failed or was "
                    + "denied); reported absent.");
        }
        return false;
    }

    /**
     * A build node is present iff some Node carries {@value #BUILD_NODE_LABEL}=true AND is amd64.
     * Any read error is fail-safe (false + warning).
     */
    private boolean buildNodePresent(K8sReader reader, List<String> warnings) {
        List<Map<String, String>> nodes;
        try {
            nodes = reader.nodeLabels();
        } catch (Exception e) {
            log.debug("[platform-capabilities] node list failed: {}", e.toString());
            warnings.add("x86 build-node presence could not be detected (Node list failed or was "
                    + "denied); reported absent.");
            return false;
        }
        for (Map<String, String> labels : nodes) {
            if (labels == null) {
                continue;
            }
            boolean labelled = "true".equalsIgnoreCase(labels.get(BUILD_NODE_LABEL));
            boolean amd64 = "amd64".equalsIgnoreCase(labels.get(ARCH_LABEL));
            if (labelled && amd64) {
                return true;
            }
        }
        return false;
    }

    /** Production {@link K8sReader}: the actual read-only fabric8 DSL calls. */
    static final class Fabric8K8sReader implements K8sReader {
        private final KubernetesClient client;

        Fabric8K8sReader(KubernetesClient client) {
            this.client = client;
        }

        @Override
        public Boolean crdInstalled(String crdName) {
            try {
                return client.apiextensions().v1().customResourceDefinitions()
                        .withName(crdName).get() != null;
            } catch (Exception e) {
                log.debug("[platform-capabilities] CRD lookup {} failed: {}", crdName, e.toString());
                return null;
            }
        }

        @Override
        public Boolean deploymentPresent(String namespace, String name) {
            try {
                return client.apps().deployments().inNamespace(namespace).withName(name).get() != null;
            } catch (Exception e) {
                log.debug("[platform-capabilities] deployment lookup {}/{} failed: {}",
                        namespace, name, e.toString());
                return null;
            }
        }

        @Override
        public List<Map<String, String>> nodeLabels() {
            List<Node> nodes = Optional.ofNullable(client.nodes().list())
                    .map(l -> l.getItems()).orElse(List.of());
            // Map each node to its label map (empty map when metadata is absent), collect to list.
            return nodes.stream()
                    .map(n -> n.getMetadata() == null ? Map.<String, String>of()
                            : Optional.ofNullable(n.getMetadata().getLabels()).orElse(Map.of()))
                    .toList();
        }
    }
}
