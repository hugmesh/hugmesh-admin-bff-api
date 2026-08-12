package net.hugmesh.adminbff.storage;

import io.fabric8.kubernetes.client.KubernetesClientBuilder;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Wires the {@link NodeStorageConfigMapWriter} the {@link NodeStorageReconciler} uses to render
 * the {@code node-storage-assignments} ConfigMap the generator's 13b ApplicationSet reads.
 *
 * <p>Mirrors {@code GamesReconcilerConfig} / {@code TestReportsConfig} EXACTLY: a
 * {@code node-storage.reconciler.enabled} flag (default false) so a cluster-less dev/test/CI
 * run — and the as-merged inert state — boots clean against the
 * {@link NoopNodeStorageConfigMapWriter}, and the REAL {@code Fabric8NodeStorageConfigMapWriter}
 * is wired ONLY when the flag is true. The fabric8 {@code KubernetesClient} is built LAZILY
 * (per apply, via the supplier) so a missing in-cluster context never fails BFF boot.
 *
 * <p>The two writer beans are gated by the SAME property with mutually-exclusive values so
 * EXACTLY ONE is registered in every mode (same reasoning as the games/test-reports configs:
 * a {@code @ConditionalOnMissingBean} no-op cannot guarantee uniqueness within one
 * {@code @Configuration}).
 *
 * <p>SHIPS DARK: the flag defaults false, so the Noop writer is in force and NOTHING is
 * written to the cluster — the {@code node-storage-assignments} ConfigMap stays as it is today
 * and 13b generates zero placements.
 */
@Configuration(proxyBeanMethods = false)
public class NodeStorageReconcilerConfig {

    /** Cluster-less default — used whenever the real writer is not enabled. */
    @Bean
    @ConditionalOnProperty(name = "node-storage.reconciler.enabled", havingValue = "false",
            matchIfMissing = true)
    NodeStorageConfigMapWriter noopNodeStorageConfigMapWriter() {
        return new NoopNodeStorageConfigMapWriter();
    }

    /** The REAL fabric8 ConfigMap writer — wired only when the reconciler is enabled. */
    @Bean
    @ConditionalOnProperty(name = "node-storage.reconciler.enabled", havingValue = "true")
    NodeStorageConfigMapWriter fabric8NodeStorageConfigMapWriter(
            @Value("${node-storage.reconciler.namespace:devops}") String namespace) {
        Fabric8NodeStorageConfigMapWriter.ClientFactory factory =
                () -> new KubernetesClientBuilder().build();
        return new Fabric8NodeStorageConfigMapWriter(factory, namespace);
    }
}
