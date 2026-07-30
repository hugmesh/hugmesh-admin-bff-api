package systems.hugmesh.adminbff.cloudbackup;

import io.fabric8.kubernetes.api.model.ConfigMap;
import io.fabric8.kubernetes.client.KubernetesClient;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import reactor.core.publisher.Flux;
import reactor.core.scheduler.Schedulers;
import systems.hugmesh.adminbff.servicecatalog.PerServiceIdentity;
import systems.hugmesh.commons.security.PrincipalDomain;

import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * The REAL {@link RunningServiceProvider}: reads the per-brand INSTALLED-SERVICES ConfigMap the
 * generator writes ({@code hugmesh-installed-services-<domainSlug>}) and returns the menu
 * filtered to what is ACTUALLY installed in the caller's brand — so a domain admin's per-service
 * backup menu reflects their brand's real footprint, not the platform's full vocabulary. Wired
 * only behind {@code app.backups.effector.enabled=true} (the SAME flag as the Velero effector,
 * see {@link BackupEffectorConfig}); otherwise the foundation's documented
 * {@code @ConditionalOnMissingBean StubRunningServiceProvider} stays the bean.
 *
 * <h3>Brand scoping</h3>
 * The ConfigMap is named per-brand off the {@link PerServiceIdentity} domain slug, so a brand-X
 * admin only ever reads brand-X's installed set. A SUPERADMIN (unscoped) reads the platform's
 * FULL documented catalog (their home-domain ConfigMap is not the right source for the
 * cross-brand view), exactly as the foundation's stub documents ("a superadmin sees the full
 * installed set").
 *
 * <h3>Safe fallback (NEVER empty the menu)</h3>
 * The catalog VOCABULARY is the foundation's documented core + optional list (delegated to the
 * stub's published list, the single source of truth for kinds/labels). The ConfigMap only acts
 * as a FILTER. When the ConfigMap is absent, empty, or unreadable (cluster blip, RBAC, a brand
 * the generator has not yet annotated) the provider falls back to the FULL documented list
 * rather than an empty menu — a missing installed-services hint must degrade to "show
 * everything", never to "back up nothing".
 *
 * <h3>Reactive boundary + dark by default</h3>
 * The blocking ConfigMap read runs on {@code boundedElastic}; the {@link KubernetesClient} is
 * supplied lazily so a missing in-cluster context never bricks boot. This is the only path that
 * does a cluster READ for the menu — gated behind the effector flag; the default path stays the
 * dark stub.
 */
public class ConfigMapRunningServiceProvider implements RunningServiceProvider {

    private static final Logger log = LoggerFactory.getLogger(ConfigMapRunningServiceProvider.class);

    /** ConfigMap name prefix; the per-brand name is {@code <prefix>-<domainSlug>}. */
    public static final String CONFIGMAP_PREFIX = "hugmesh-installed-services";

    /** Supplies a configured client; separated so it can be stubbed in tests. */
    @FunctionalInterface
    public interface ClientFactory {
        KubernetesClient get();
    }

    private final ClientFactory clientFactory;
    private final String namespace;
    /** The published catalog vocabulary (kinds/labels) — reuses the foundation stub so there is
     *  ONE source of truth for what a service IS; this provider only filters it. */
    private final RunningServiceProvider catalog;

    public ConfigMapRunningServiceProvider(ClientFactory clientFactory, String namespace,
                                           RunningServiceProvider catalog) {
        this.clientFactory = clientFactory;
        this.namespace = (namespace == null || namespace.isBlank()) ? "hugmesh-backend" : namespace.trim();
        this.catalog = catalog == null ? new StubRunningServiceProvider() : catalog;
    }

    @Override
    public Flux<RunningService> runningServices(PrincipalDomain scope) {
        // The full documented catalog (kinds/labels) for this scope.
        Flux<RunningService> full = catalog.runningServices(scope);

        // SUPERADMIN (unscoped) sees the full catalog — no per-brand ConfigMap filter.
        if (scope == null || !scope.scoped()) {
            return full;
        }

        String domain = scope.domain();
        return readInstalledKeys(domain)
                .flatMapMany(installed -> {
                    if (installed.isEmpty()) {
                        // Fallback: no readable installed-services hint -> show everything.
                        log.debug("[cloud-backup] no installed-services ConfigMap for domain '{}'"
                                + " — menu falls back to the full documented catalog", domain);
                        return full;
                    }
                    // Filter the catalog to the brand's installed keys (case-insensitive).
                    return full.filter(svc -> installed.contains(svc.key().toLowerCase()));
                });
    }

    /** Read the brand's installed-services keys from its ConfigMap. Empty set on absent/blank/
     *  error (the caller falls back to the full catalog). The read is wrapped on
     *  boundedElastic and NEVER throws to the subscriber. */
    private reactor.core.publisher.Mono<Set<String>> readInstalledKeys(String domain) {
        String cmName = CONFIGMAP_PREFIX + "-" + PerServiceIdentity.slug(domain);
        // Blocking Kubernetes API call dispatched on boundedElastic; empty set on any error.
        return reactor.core.publisher.Mono.fromCallable(() -> loadKeysFromConfigMap(cmName))
                .subscribeOn(Schedulers.boundedElastic())
                .onErrorResume(t -> {
                    log.warn("[cloud-backup] installed-services ConfigMap '{}' read failed"
                            + " (menu falls back to full catalog): {}", cmName, t.toString());
                    return reactor.core.publisher.Mono.just(Set.<String>of());
                });
    }

    /** Blocking: load the installed-service keys from a ConfigMap; returns an empty set when absent. */
    private Set<String> loadKeysFromConfigMap(String cmName) {
        Set<String> keys = new LinkedHashSet<>();
        try (KubernetesClient client = clientFactory.get()) {
            ConfigMap cm = client.configMaps().inNamespace(namespace).withName(cmName).get();
            if (cm != null && cm.getData() != null) {
                for (String k : cm.getData().keySet()) {
                    if (k != null && !k.isBlank()) {
                        keys.add(k.trim().toLowerCase());
                    }
                }
            }
        }
        return keys;
    }

    /** Visible for testing: the per-brand ConfigMap name for a domain. */
    static String configMapName(String domain) {
        return CONFIGMAP_PREFIX + "-" + PerServiceIdentity.slug(domain);
    }

    /** Visible for testing: the documented catalog keys (the union the stub publishes). */
    static List<String> catalogKeys(RunningServiceProvider catalog, PrincipalDomain scope) {
        return catalog.runningServices(scope).map(RunningService::key).collectList().block();
    }
}
