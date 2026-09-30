package net.hugmesh.adminbff.gamesservices;

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
 * The REAL per-domain instance ConfigMap writer: server-side-applies a ConfigMap named
 * {@code games-instances-<domain>} in the games namespace, whose data is the desired set of
 * ACTIVE instances for that domain (one entry per instance, value = a small render spec the
 * generator's apps/13c ApplicationSet expands into a Deployment/Service/PVC).
 *
 * <p>Clones the {@link Fabric8JobLauncherShape} (the test-reports {@code Fabric8JobLauncher})
 * pattern: a {@code ClientFactory} provider so the client is built lazily (a transient
 * API-server blip must not fail the reconcile tick), and ALL exceptions are swallowed to a
 * false return so a failed apply is retried on the next tick via {@code propagation_state}
 * rather than crashing the loop. The client's acquire/apply/close lifecycle is expressed with
 * {@code Mono.usingWhen} (acquire lazily, apply, ALWAYS close — success, error, or
 * cancellation — mirroring what try-with-resources guaranteed), offloaded onto
 * {@code Schedulers.boundedElastic()} since the fabric8 client does blocking I/O; the public
 * {@link #writeDomainConfigMap} contract stays a plain synchronous {@code boolean} so the
 * Lease-gated reconciler's call site is unchanged.
 *
 * <p>admin-bff is the SINGLE writer; this is only ever called from the Lease-gated
 * reconciler (one writer at a time), so a server-side replace of the whole ConfigMap is
 * safe — there is no second writer to race.
 */
public class Fabric8InstanceConfigMapWriter implements InstanceConfigMapWriter {

    private static final Logger log = LoggerFactory.getLogger(Fabric8InstanceConfigMapWriter.class);

    /** Supplies a configured client; separated so it can be stubbed in tests. */
    @FunctionalInterface
    public interface ClientFactory {
        KubernetesClient get();
    }

    /** Marker for the doc-reference above (the test-reports launcher we clone). */
    interface Fabric8JobLauncherShape {}

    private final ClientFactory clientFactory;
    private final String namespace;

    public Fabric8InstanceConfigMapWriter(ClientFactory clientFactory, String namespace) {
        this.clientFactory = clientFactory;
        this.namespace = (namespace == null || namespace.isBlank()) ? "hugmesh-games" : namespace;
    }

    private Boolean applyConfigMap(KubernetesClient client, String cmName, String domain,
                                   Map<String, String> data) {
        ConfigMap cm = new ConfigMapBuilder()
                .withNewMetadata()
                .withName(cmName)
                .withNamespace(namespace)
                .addToLabels("app.kubernetes.io/part-of", "hugmesh.net")
                .addToLabels("hugmesh.net/games-instances-domain", sanitize(domain))
                .endMetadata()
                .withData(data)
                .build();
        // Server-side replace: the ConfigMap IS the desired set, single-writer.
        client.configMaps().inNamespace(namespace).resource(cm).serverSideApply();
        log.info("[games-reconciler] applied ConfigMap {}/{} ({} active instance(s))",
                namespace, cmName, data.size());
        return Boolean.TRUE;
    }

    @Override
    public Mono<Boolean> writeDomainConfigMap(String domain, List<GameInstance> instances) {
        String cmName = "games-instances-" + sanitize(domain);
        Map<String, String> data = new LinkedHashMap<>();
        if (instances != null) {
            for (GameInstance i : instances) {
                // One entry per instance; the generator ApplicationSet keys its list
                // generator on these. Keep the value a compact, render-only spec
                // (slug/name/node_port/console_path) — never secrets.
                String key = sanitize(i.slug()) + "-" + sanitize(i.name());
                data.put(key, renderSpec(i));
            }
        }
        // Reactive resource lifecycle: Mono.usingWhen acquires the client lazily
        // (clientFactory::get, off the caller's thread via boundedElastic — a
        // transient API-server blip / DNS lookup must not run on an event-loop
        // thread), runs the server-side apply, and ALWAYS closes the client
        // afterwards (success, error, or cancellation) — the same
        // always-closes guarantee try-with-resources gave, expressed reactively.
        // The public contract stays synchronous (a plain boolean, swallowing every
        // failure to false for retry-next-tick), so callers are unchanged.
        return Mono.usingWhen(
                        Mono.fromCallable(clientFactory::get),
                        client -> Mono.fromCallable(() -> applyConfigMap(client, cmName, domain, data)),
                        client -> Mono.fromRunnable(client::close))
                .subscribeOn(Schedulers.boundedElastic())
                .onErrorResume(KubernetesClientException.class, e -> {
                    log.warn("[games-reconciler] ConfigMap apply for domain '{}' failed (retry next tick): {}",
                            domain, e.getMessage());
                    return Mono.just(Boolean.FALSE);
                })
                .onErrorResume(Exception.class, e -> {
                    log.warn("[games-reconciler] ConfigMap apply for domain '{}' errored (retry next tick): {}",
                            domain, e.toString());
                    return Mono.just(Boolean.FALSE);
                });
    }

    @Override
    public boolean isReal() {
        return true;
    }

    /** A compact, secret-free render spec the ApplicationSet expands. */
    private static String renderSpec(GameInstance i) {
        return "slug=" + i.slug() + ";name=" + i.name()
                + ";nodePort=" + (i.nodePort() == null ? "" : i.nodePort())
                + ";consolePath=" + (i.consolePath() == null ? "" : i.consolePath());
    }

    /** k8s name-safe lowercasing (label/name DNS-1123-ish); keeps the writer total. */
    private static String sanitize(String s) {
        if (s == null) return "default";
        String out = s.toLowerCase().replaceAll("[^a-z0-9.-]", "-");
        return out.isBlank() ? "default" : out;
    }
}
