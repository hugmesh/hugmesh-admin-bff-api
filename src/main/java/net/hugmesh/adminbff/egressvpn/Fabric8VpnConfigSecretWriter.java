package net.hugmesh.adminbff.egressvpn;

import io.fabric8.kubernetes.api.model.Secret;
import io.fabric8.kubernetes.api.model.SecretBuilder;
import io.fabric8.kubernetes.client.KubernetesClient;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

/**
 * The REAL {@link VpnConfigSecretWriter}: server-side-applies the per-config K8s Secret the
 * node-level {@code hugmesh-vpn-reconcile} agent reads (name = data key = the row's
 * {@code secretRef}, so a default Secret volume projection materialises exactly the
 * {@code ${VPN_SECRET_DIR}/<secretRef>} file the agent resolves).
 *
 * <p>Clones {@link net.hugmesh.adminbff.gamesservices.Fabric8InstanceConfigMapWriter}: a
 * {@code ClientFactory} so the client is built LAZILY per write (a missing in-cluster context
 * never fails BFF boot), {@code Mono.usingWhen} for the acquire/apply/ALWAYS-close lifecycle on
 * {@code Schedulers.boundedElastic()} (fabric8 does blocking I/O), and EVERY failure swallowed
 * to {@code false} — a failed delivery leaves the row's {@code propagationState} visibly
 * {@code pending} and the node on its key-USB fallback, never a failed import.
 *
 * <p>{@code stringData} carries the raw config text (the API server base64-encodes it into
 * {@code data}); admin-bff is the single writer of these Secrets, so a whole-object server-side
 * apply is safe. REDACTION: the body (the private VPN key) is NEVER logged — only its length.
 */
public class Fabric8VpnConfigSecretWriter implements VpnConfigSecretWriter {

    private static final Logger log = LoggerFactory.getLogger(Fabric8VpnConfigSecretWriter.class);

    /** Supplies a configured client; separated so it can be stubbed in tests. */
    @FunctionalInterface
    public interface ClientFactory {
        KubernetesClient get();
    }

    private final ClientFactory clientFactory;
    private final String namespace;

    public Fabric8VpnConfigSecretWriter(ClientFactory clientFactory, String namespace) {
        this.clientFactory = clientFactory;
        this.namespace = (namespace == null || namespace.isBlank()) ? "hugmesh-backend" : namespace;
    }

    @Override
    public Mono<Boolean> write(String secretRef, String domain, String name, String kind,
                               String configBody) {
        return Mono.usingWhen(
                        Mono.fromCallable(clientFactory::get),
                        client -> Mono.fromCallable(() -> apply(client, secretRef, domain, name,
                                kind, configBody)),
                        client -> Mono.fromRunnable(client::close))
                .subscribeOn(Schedulers.boundedElastic())
                // Best-effort: a cluster failure degrades to pending + key-USB fallback,
                // never a failed import. (No config bytes in the log line.)
                .onErrorResume(Exception.class, e -> {
                    log.warn("[egress-vpn] Secret delivery for {}/{} (secretRef={}) failed — "
                            + "row stays pending, node keeps its key-USB config: {}",
                            domain, name, secretRef, e.toString());
                    return Mono.just(Boolean.FALSE);
                });
    }

    private Boolean apply(KubernetesClient client, String secretRef, String domain, String name,
                          String kind, String configBody) {
        Secret secret = new SecretBuilder()
                .withNewMetadata()
                .withName(secretRef)
                .withNamespace(namespace)
                .addToLabels("app.kubernetes.io/part-of", "hugmesh.systems")
                .addToLabels("snapdragon.systems/optional-service", "egress-vpn")
                .addToLabels("snapdragon.systems/vpn-config-domain", sanitize(domain))
                .endMetadata()
                .withType("Opaque")
                .addToStringData(secretRef, configBody)
                .build();
        client.secrets().inNamespace(namespace).resource(secret).serverSideApply();
        log.info("[egress-vpn] applied Secret {}/{} for config {}/{} kind={} ({} chars)",
                namespace, secretRef, domain, name, kind,
                configBody == null ? 0 : configBody.length());
        return Boolean.TRUE;
    }

    @Override
    public boolean isReal() {
        return true;
    }

    /** k8s label-value-safe lowercasing; keeps the writer total on odd domains. */
    private static String sanitize(String s) {
        if (s == null) return "unknown";
        String out = s.toLowerCase().replaceAll("[^a-z0-9.-]", "-");
        return out.isBlank() ? "unknown" : out;
    }
}
