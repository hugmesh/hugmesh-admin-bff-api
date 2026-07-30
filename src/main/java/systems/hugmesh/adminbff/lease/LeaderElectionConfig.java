package systems.hugmesh.adminbff.lease;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Picks the {@link LeaderElection} primitive for the access_suspension reconcile
 * loop, config-only:
 *
 * <ul>
 *   <li>{@code app.access-suspension.lease.enabled=true} (in-cluster, multi-replica)
 *       → {@link KubernetesLeaderElection}, driven by the spring-cloud-kubernetes
 *       fabric8 {@code Lease} leader-election machinery (which the deployment also
 *       enables via {@code spring.cloud.kubernetes.enabled=true} +
 *       {@code spring.cloud.kubernetes.leader.enabled=true});</li>
 *   <li>otherwise (the DEFAULT — single replica / dev / test / CI) →
 *       {@link AlwaysLeader}, so the loop is unconditionally the writer and no k8s
 *       API is dialed.</li>
 * </ul>
 *
 * <p>The two beans are mutually exclusive on the same property so exactly one
 * {@link LeaderElection} is ever present for the loop to inject.
 */
@Configuration(proxyBeanMethods = false)
public class LeaderElectionConfig {

    @Bean
    @ConditionalOnProperty(name = "app.access-suspension.lease.enabled", havingValue = "true")
    LeaderElection kubernetesLeaderElection(
            @Value("${app.access-suspension.lease.role:access-suspension}") String role) {
        return new KubernetesLeaderElection(role);
    }

    @Bean
    @ConditionalOnProperty(name = "app.access-suspension.lease.enabled", havingValue = "false",
            matchIfMissing = true)
    LeaderElection alwaysLeader() {
        return new AlwaysLeader();
    }
}
