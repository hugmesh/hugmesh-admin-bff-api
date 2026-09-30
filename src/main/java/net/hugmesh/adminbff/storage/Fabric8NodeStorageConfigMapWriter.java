package net.hugmesh.adminbff.storage;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.fabric8.kubernetes.api.model.ConfigMap;
import io.fabric8.kubernetes.api.model.ConfigMapBuilder;
import io.fabric8.kubernetes.client.KubernetesClient;
import io.fabric8.kubernetes.client.KubernetesClientException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

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
 * are swallowed to a {@code false} emission so a failed apply is retried on the next tick via
 * {@code propagation_state} rather than crashing the loop. The client's acquire/apply/close
 * lifecycle is expressed with {@code Mono.usingWhen} (acquire lazily, apply, ALWAYS close —
 * success, error, or cancellation — mirroring what try-with-resources guaranteed), offloaded
 * onto {@code Schedulers.boundedElastic()} since the fabric8 client does blocking I/O.
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

    private Boolean applyConfigMap(KubernetesClient client, Map<String, String> data, int count) {
        ConfigMap cm = new ConfigMapBuilder()
                .withNewMetadata()
                .withName(CONFIGMAP_NAME)
                .withNamespace(namespace)
                .addToLabels("app.kubernetes.io/part-of", "hugmesh.net")
                .addToLabels("hugmesh.net/node-storage-assignments", "true")
                .endMetadata()
                .withData(data)
                .build();
        // Server-side replace: the ConfigMap IS the desired set, single-writer.
        client.configMaps().inNamespace(namespace).resource(cm).serverSideApply();
        log.info("[node-storage-reconciler] applied ConfigMap {}/{} ({} active element(s))",
                namespace, CONFIGMAP_NAME, count);
        return Boolean.TRUE;
    }

    @Override
    public Mono<Boolean> writeAssignments(List<StorageAssignmentElement> elements) {
        String json = renderElementsJson(elements);
        Map<String, String> data = new LinkedHashMap<>();
        data.put(ELEMENTS_KEY, json);
        int count = elements == null ? 0 : elements.size();
        // Reactive resource lifecycle: Mono.usingWhen acquires the client LAZILY
        // (clientFactory::get), runs the server-side apply, and ALWAYS closes the client
        // afterwards — success, error, or cancellation — the same always-closes guarantee
        // try-with-resources gave, expressed reactively. subscribeOn(boundedElastic) keeps
        // both the acquire (a DNS lookup / API-server handshake) and the blocking apply off
        // the reconciler's reactive thread; the previous synchronous body ran the whole
        // fabric8 round-trip on whichever thread delivered the upstream signal.
        return Mono.usingWhen(
                        Mono.fromCallable(() -> requireClient(clientFactory.get())),
                        client -> Mono.fromCallable(() -> applyConfigMap(client, data, count)),
                        client -> Mono.fromRunnable(client::close))
                .subscribeOn(Schedulers.boundedElastic())
                .onErrorResume(KubernetesClientException.class, e -> {
                    log.warn("[node-storage-reconciler] ConfigMap apply failed (retry next tick): {}",
                            e.getMessage());
                    return Mono.just(Boolean.FALSE);
                })
                .onErrorResume(Exception.class, e -> {
                    log.warn("[node-storage-reconciler] ConfigMap apply errored (retry next tick): {}",
                            e.toString());
                    return Mono.just(Boolean.FALSE);
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
