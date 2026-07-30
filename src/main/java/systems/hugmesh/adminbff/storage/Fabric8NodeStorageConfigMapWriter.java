package systems.hugmesh.adminbff.storage;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.fabric8.kubernetes.api.model.ConfigMap;
import io.fabric8.kubernetes.api.model.ConfigMapBuilder;
import io.fabric8.kubernetes.client.KubernetesClient;
import io.fabric8.kubernetes.client.KubernetesClientException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * The REAL node-storage assignments ConfigMap writer: server-side-applies a ConfigMap named
 * {@code node-storage-assignments} in the devops namespace (where the 13b ApplicationSet
 * lives), whose single {@code elements} key holds the JSON array of ACTIVE assignment
 * elements the generator's {@code apps/13b-node-storage.yaml} list-generator consumes (one
 * placement Application per element). The ConfigMap IS the desired set.
 *
 * <p>Clones the games {@link Fabric8InstanceConfigMapWriter} / test-reports
 * {@code Fabric8JobLauncher} pattern: a {@code ClientFactory} provider so the client is built
 * LAZILY (a transient API-server blip must not fail the reconcile tick), and ALL exceptions
 * are swallowed to a {@code false} return so a failed apply is retried on the next tick via
 * {@code propagation_state} rather than crashing the loop.
 *
 * <p>admin-bff is the SINGLE writer; this is only ever called from the Lease-gated reconciler
 * (one writer at a time), so a server-side replace of the whole ConfigMap is safe — there is
 * no second writer to race.
 */
public class Fabric8NodeStorageConfigMapWriter implements NodeStorageConfigMapWriter {

    private static final Logger log =
            LoggerFactory.getLogger(Fabric8NodeStorageConfigMapWriter.class);

    /** The ConfigMap the 13b ApplicationSet mirrors its element list from. */
    static final String CONFIGMAP_NAME = "node-storage-assignments";

    /** The single data key holding the JSON array of elements. */
    static final String ELEMENTS_KEY = "elements";

    /** Supplies a configured client; separated so it can be stubbed in tests. */
    @FunctionalInterface
    public interface ClientFactory {
        KubernetesClient get();
    }

    private final ClientFactory clientFactory;
    private final String namespace;
    private final ObjectMapper mapper = new ObjectMapper();

    public Fabric8NodeStorageConfigMapWriter(ClientFactory clientFactory, String namespace) {
        this.clientFactory = clientFactory;
        this.namespace = (namespace == null || namespace.isBlank()) ? "devops" : namespace;
    }

    @Override
    public boolean writeAssignments(List<StorageAssignmentElement> elements) {
        String json = renderElementsJson(elements);
        Map<String, String> data = new LinkedHashMap<>();
        data.put(ELEMENTS_KEY, json);
        // TODO reactive: consider Mono.usingWhen(Mono.fromCallable(clientFactory::get), ...) for the KubernetesClient lifecycle
        try (KubernetesClient client = clientFactory.get()) {
            ConfigMap cm = new ConfigMapBuilder()
                    .withNewMetadata()
                    .withName(CONFIGMAP_NAME)
                    .withNamespace(namespace)
                    .addToLabels("app.kubernetes.io/part-of", "hugmesh.systems")
                    .addToLabels("hugmesh.systems/node-storage-assignments", "true")
                    .endMetadata()
                    .withData(data)
                    .build();
            // Server-side replace: the ConfigMap IS the desired set, single-writer.
            client.configMaps().inNamespace(namespace).resource(cm).serverSideApply();
            log.info("[node-storage-reconciler] applied ConfigMap {}/{} ({} active element(s))",
                    namespace, CONFIGMAP_NAME, elements == null ? 0 : elements.size());
            return true;
        } catch (KubernetesClientException e) {
            log.warn("[node-storage-reconciler] ConfigMap apply failed (retry next tick): {}",
                    e.getMessage());
            return false;
        } catch (Exception e) {
            log.warn("[node-storage-reconciler] ConfigMap apply errored (retry next tick): {}",
                    e.toString());
            return false;
        }
    }

    @Override
    public boolean isReal() {
        return true;
    }

    /**
     * Render the elements into the JSON array string the 13b list-generator consumes. An empty
     * / null list renders {@code []} (the inert default). Package-visible + total so the
     * serialization is unit-testable in isolation.
     */
    String renderElementsJson(List<StorageAssignmentElement> elements) {
        ArrayNode arr = mapper.createArrayNode();
        if (elements != null) {
            for (StorageAssignmentElement e : elements) {
                ObjectNode o = mapper.createObjectNode();
                o.put("id", nz(e.id()));
                o.put("service", nz(e.service()));
                o.put("pvc", nz(e.pvc()));
                o.put("nodeName", nz(e.nodeName()));
                o.put("poolPath", nz(e.poolPath()));
                o.put("namespace", nz(e.namespace()));
                o.put("requested", nz(e.requested()));
                o.put("state", nz(e.state()));
                arr.add(o);
            }
        }
        return arr.toString();
    }

    private static String nz(String s) {
        return s == null ? "" : s;
    }
}
