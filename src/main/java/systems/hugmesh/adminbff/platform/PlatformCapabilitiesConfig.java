package systems.hugmesh.adminbff.platform;

import io.fabric8.kubernetes.client.KubernetesClientBuilder;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Wires the {@link PlatformCapabilityProbe} the {@link PlatformCapabilitiesController} reports
 * through. Mirrors {@code TestReportsConfig} / {@code GamesReconcilerConfig} EXACTLY: ONE flag
 * ({@code app.platform-capabilities.k8s.enabled}, default false) gates two mutually-exclusive
 * beans on the SAME property — the real one on {@code havingValue="true"} and the no-op on
 * {@code havingValue="false", matchIfMissing=true} — so EXACTLY ONE {@link PlatformCapabilityProbe}
 * is registered in every mode (the {@code @ConditionalOnMissingBean} approach can register both
 * within one {@code @Configuration}).
 *
 * <p>The fabric8 client is built LAZILY (per probe, via the {@link
 * Fabric8PlatformCapabilityProbe.ClientFactory} supplier) so a missing in-cluster context never
 * fails BFF boot — only an actual probe touches the API server, and even then it fails SAFE.
 */
@Configuration(proxyBeanMethods = false)
public class PlatformCapabilitiesConfig {

    /** Cluster-less default — used whenever the k8s probe is not enabled. */
    @Bean
    @ConditionalOnProperty(name = "app.platform-capabilities.k8s.enabled", havingValue = "false",
            matchIfMissing = true)
    PlatformCapabilityProbe noopPlatformCapabilityProbe() {
        return new NoopPlatformCapabilityProbe();
    }

    /** The REAL read-only fabric8 probe — wired only when the k8s probe is enabled. */
    @Bean
    @ConditionalOnProperty(name = "app.platform-capabilities.k8s.enabled", havingValue = "true")
    PlatformCapabilityProbe fabric8PlatformCapabilityProbe() {
        // Lazy client: built on each probe, not at boot — a transient API-server outage must not
        // brick the BFF. The in-cluster ServiceAccount / kubeconfig is auto-discovered.
        Fabric8PlatformCapabilityProbe.ClientFactory factory =
                () -> new KubernetesClientBuilder().build();
        return new Fabric8PlatformCapabilityProbe(factory);
    }
}
