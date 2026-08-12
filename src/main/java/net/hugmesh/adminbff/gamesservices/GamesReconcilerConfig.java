package net.hugmesh.adminbff.gamesservices;

import io.fabric8.kubernetes.client.KubernetesClientBuilder;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Wires the {@link InstanceConfigMapWriter} the {@link GameInstanceReconciler} uses to
 * render per-domain ACTIVE-instance ConfigMaps.
 *
 * <p>Mirrors {@code TestReportsConfig} EXACTLY (and the {@code LeaderElectionConfig} flag
 * shape): a {@code games-services.reconciler.enabled} flag (default false) so a cluster-less
 * dev/test/CI run boots clean against the {@link NoopInstanceConfigMapWriter}, and the REAL
 * {@link Fabric8InstanceConfigMapWriter} is wired ONLY when the flag is true. The fabric8
 * {@code KubernetesClient} is built LAZILY (per apply, via the supplier) so a missing
 * in-cluster context never fails BFF boot.
 *
 * <p>The two writer beans are gated by the SAME property with mutually-exclusive values so
 * EXACTLY ONE is registered in every mode (same reasoning as {@code TestReportsConfig}: a
 * {@code @ConditionalOnMissingBean} no-op cannot guarantee uniqueness within one
 * {@code @Configuration}).
 */
@Configuration(proxyBeanMethods = false)
public class GamesReconcilerConfig {

    /** Cluster-less default — used whenever the real writer is not enabled. */
    @Bean
    @ConditionalOnProperty(name = "games-services.reconciler.enabled", havingValue = "false",
            matchIfMissing = true)
    InstanceConfigMapWriter noopInstanceConfigMapWriter() {
        return new NoopInstanceConfigMapWriter();
    }

    /** The REAL fabric8 ConfigMap writer — wired only when the reconciler is enabled. */
    @Bean
    @ConditionalOnProperty(name = "games-services.reconciler.enabled", havingValue = "true")
    InstanceConfigMapWriter fabric8InstanceConfigMapWriter(
            @Value("${games-services.reconciler.namespace:hugmesh-games}") String namespace) {
        Fabric8InstanceConfigMapWriter.ClientFactory factory =
                () -> new KubernetesClientBuilder().build();
        return new Fabric8InstanceConfigMapWriter(factory, namespace);
    }
}
