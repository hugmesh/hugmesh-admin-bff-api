package net.hugmesh.adminbff.testreports;

import io.fabric8.kubernetes.client.KubernetesClientBuilder;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Wires the {@link JobLauncher} the {@link TestRunOrchestrator} uses to launch the
 * test-runner Job.
 *
 * <p>Mirrors the {@code HomeserverAdminConfig} / {@code AnnouncementConfig}
 * enabled-flag pattern: a {@code testreports.launch.enabled} flag (default false) so
 * a cluster-less dev/test/CI run boots clean against the {@link NoopJobLauncher},
 * and the REAL {@link Fabric8JobLauncher} is wired ONLY when the flag is true. The
 * fabric8 {@code KubernetesClient} is built LAZILY (per apply, via the supplier) so
 * a missing in-cluster context never fails BFF boot — only an actual launch attempt
 * touches the API server.
 *
 * <p>The two {@link JobLauncher} beans are gated by the <em>same</em>
 * {@code testreports.launch.enabled} property with mutually-exclusive values — the
 * real one on {@code havingValue="true"} and the no-op one on
 * {@code havingValue="false", matchIfMissing=true} — so EXACTLY ONE
 * {@link JobLauncher} is registered in every mode. (A {@code @ConditionalOnMissingBean}
 * gate on the no-op cannot guarantee this: within a single {@code @Configuration} the
 * no-op bean method is evaluated BEFORE the real bean is registered, so the missing-bean
 * condition matches and BOTH beans register when the flag is true — a
 * {@code NoUniqueBeanDefinitionException} at injection into {@link TestRunOrchestrator},
 * which bricks launch-enabled deploys.)
 *
 * <p>The launch namespace defaults to {@code hugmesh-backend} (the BFF's own
 * namespace, where the {@code test-runner} ServiceAccount + RBAC live) and is
 * overridable for a branded/relocated deployment.
 */
@Configuration(proxyBeanMethods = false)
public class TestReportsConfig {

    /** Cluster-less default — used whenever the real launcher is not enabled. */
    @Bean
    @ConditionalOnProperty(name = "testreports.launch.enabled", havingValue = "false", matchIfMissing = true)
    JobLauncher noopJobLauncher() {
        return new NoopJobLauncher();
    }

    /** The REAL fabric8 launcher — wired only when testreports.launch.enabled=true. */
    @Bean
    @ConditionalOnProperty(name = "testreports.launch.enabled", havingValue = "true")
    JobLauncher fabric8JobLauncher(
            @Value("${testreports.launch.namespace:hugmesh-backend}") String namespace) {
        // Lazy client: built on first apply, not at boot — a transient API-server
        // outage must not brick the BFF. The in-cluster ServiceAccount / kubeconfig
        // is auto-discovered by the fabric8 default config.
        Fabric8JobLauncher.ClientFactory factory = () -> new KubernetesClientBuilder().build();
        return new Fabric8JobLauncher(factory, namespace);
    }
}
