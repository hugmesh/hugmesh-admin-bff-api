package systems.hugmesh.adminbff.optionalservices;

import io.fabric8.kubernetes.client.KubernetesClientBuilder;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Wires the three seams the {@link OptionalServiceReconciler} uses (the CR client, the 13a
 * ApplicationSet patcher, the installed-services ConfigMap writer). Mirrors
 * {@code NodeStorageReconcilerConfig} / {@code BackupEffectorConfig} EXACTLY: a single
 * {@code app.optional-services.reconcile.enabled} flag (default false) selects the Noop
 * (cluster-less) implementation of each seam, and the REAL fabric8 implementations are
 * wired ONLY when the flag is true. Each pair is gated by the SAME property with
 * mutually-exclusive values so EXACTLY ONE bean of each seam is registered in every mode.
 * The fabric8 {@code KubernetesClient} is built LAZILY (per call, via the supplier) so a
 * missing in-cluster context never fails BFF boot.
 *
 * <p>SHIPS DARK: the flag defaults false, so all three Noop seams are in force and NOTHING
 * is written to the cluster — 13a + the installed-services ConfigMap stay whatever the
 * build rendered, and the reconciler's scheduled tick reads an empty CR list and no-ops.
 * The {@link OptionalServiceReconciler} itself is always registered (a {@code @Service},
 * like {@code NodeStorageReconciler}); only these seams flip it live.
 *
 * <p>⚠ Enabling this flag on a live cluster requires the hardcoded-app CUT-OVER first (see
 * {@code docs/OPTIONAL-SERVICES.md §10}) — otherwise flipping akkoma/tuwunel/phpbb on
 * makes the ApplicationSet double-manage the still-present hardcoded apps.
 */
@Configuration(proxyBeanMethods = false)
public class OptionalServiceReconcilerConfig {

    private static final String ENABLED = "app.optional-services.reconcile.enabled";

    // ── OptionalService CR client (read spec + write status) ─────────────────────────
    @Bean
    @ConditionalOnProperty(name = ENABLED, havingValue = "false", matchIfMissing = true)
    OptionalServiceClient noopOptionalServiceClient() {
        return new NoopOptionalServiceClient();
    }

    @Bean
    @ConditionalOnProperty(name = ENABLED, havingValue = "true")
    OptionalServiceClient fabric8OptionalServiceClient(
            @Value("${app.optional-services.reconcile.namespace:devops}") String namespace) {
        Fabric8OptionalServiceClient.ClientFactory factory = () -> new KubernetesClientBuilder().build();
        return new Fabric8OptionalServiceClient(factory, namespace);
    }

    // ── 13a ApplicationSet element patcher (the runtime add/remove lever) ────────────
    @Bean
    @ConditionalOnProperty(name = ENABLED, havingValue = "false", matchIfMissing = true)
    OptionalServiceApplicationSetPatcher noopOptionalServiceApplicationSetPatcher() {
        return new NoopOptionalServiceApplicationSetPatcher();
    }

    @Bean
    @ConditionalOnProperty(name = ENABLED, havingValue = "true")
    OptionalServiceApplicationSetPatcher fabric8OptionalServiceApplicationSetPatcher(
            @Value("${app.optional-services.reconcile.namespace:devops}") String namespace) {
        Fabric8OptionalServiceApplicationSetPatcher.ClientFactory factory =
                () -> new KubernetesClientBuilder().build();
        return new Fabric8OptionalServiceApplicationSetPatcher(factory, namespace);
    }

    // ── installed-services ConfigMap greying mirror ──────────────────────────────────
    @Bean
    @ConditionalOnProperty(name = ENABLED, havingValue = "false", matchIfMissing = true)
    InstalledServicesConfigMapWriter noopInstalledServicesConfigMapWriter() {
        return new NoopInstalledServicesConfigMapWriter();
    }

    @Bean
    @ConditionalOnProperty(name = ENABLED, havingValue = "true")
    InstalledServicesConfigMapWriter fabric8InstalledServicesConfigMapWriter(
            OptionalServiceRegistry registry,
            @Value("${app.optional-services.reconcile.policy-namespace:hugmesh-policy}") String namespace) {
        Fabric8InstalledServicesConfigMapWriter.ClientFactory factory =
                () -> new KubernetesClientBuilder().build();
        return new Fabric8InstalledServicesConfigMapWriter(factory, namespace, registry.slugs());
    }
}
