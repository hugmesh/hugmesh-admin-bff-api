package net.hugmesh.adminbff.backingservices;

import io.fabric8.kubernetes.client.KubernetesClientBuilder;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Wires the {@link BackingServiceEffector} seam the {@link BackingServiceModeReconciler} uses.
 *
 * <p>Two beans gated by the SAME property with mutually-exclusive values, so EXACTLY ONE is
 * registered in every mode — the {@code OptionalServiceReconcilerConfig} idiom, which is
 * deterministic where relying on {@code @ConditionalOnMissingBean} ordering between two plain
 * {@code @Configuration} classes is not. The {@code @ConditionalOnMissingBean} on the Noop is
 * kept so a third-party override still wins.
 *
 * <p><b>SHIPS DARK.</b> {@code app.backing-services.effector.enabled} defaults false, so the
 * dark {@link NoopBackingServiceEffector} is in force and NO cluster is dialled at defaults —
 * a recorded managed mode stays durable INTENT. The real
 * {@link Fabric8BackingServiceEffector} is wired only when the flag is true, and even then the
 * reconcile loop that calls it has its own flag
 * ({@code app.backing-services.reconcile.enabled}, also default false).
 *
 * <p>⚠ Enabling this flag on a live cluster needs three things to be true first, or the write
 * lands and does nothing visible: the {@code backing-service-endpoints} ConfigMap must exist in
 * the target namespace (generator {@code apps/17-backing-service-endpoints.yaml}); the
 * {@code backing-service-endpoints-writer} Role must be bound to this pod's
 * {@code backups-effector} ServiceAccount there; and the consumer Deployments must actually read
 * the ConfigMap keys — until that conversion lands, a flip rewrites a key nothing consumes and
 * rolls a pod that re-reads its own literal. The fabric8 {@code KubernetesClient} is built
 * LAZILY (per call, via the supplier) so a missing in-cluster context never fails BFF boot.
 */
@Configuration(proxyBeanMethods = false)
public class BackingServiceEffectorConfig {

    private static final String ENABLED = "app.backing-services.effector.enabled";

    @Bean
    @ConditionalOnProperty(name = ENABLED, havingValue = "false", matchIfMissing = true)
    @ConditionalOnMissingBean
    BackingServiceEffector noopBackingServiceEffector() {
        return new NoopBackingServiceEffector();
    }

    @Bean
    @ConditionalOnProperty(name = ENABLED, havingValue = "true")
    BackingServiceEffector fabric8BackingServiceEffector() {
        Fabric8BackingServiceEffector.ClientFactory factory =
                () -> new KubernetesClientBuilder().build();
        return new Fabric8BackingServiceEffector(factory);
    }
}
