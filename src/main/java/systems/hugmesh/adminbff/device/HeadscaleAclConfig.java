package systems.hugmesh.adminbff.device;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.reactive.function.client.WebClient;
import systems.hugmesh.adminbff.lease.LeaderElection;

/**
 * Wires the LAYER-A headscale ACL PUSH client + reconcile loop. Mirrors
 * {@code GamesReconcilerConfig} EXACTLY (the dark-effector seam) + {@code RegistryHeadscaleConfig}
 * (the config-only headscale seam):
 *
 * <ul>
 *   <li>{@link HeadscaleAclProperties} bound on {@code app.registry.headscale-acl.*};</li>
 *   <li>the {@link HeadscalePolicyClient} is the cluster-less {@link NoopHeadscalePolicyClient}
 *       by default and the REAL {@link WebClientHeadscalePolicyClient} ONLY when
 *       {@code app.registry.headscale-acl.enabled=true} — two beans gated by the SAME property
 *       with mutually-exclusive values so EXACTLY ONE is registered in every mode (same
 *       reasoning as {@code GamesReconcilerConfig}: a {@code @ConditionalOnMissingBean} no-op
 *       cannot guarantee uniqueness within one {@code @Configuration});</li>
 *   <li>the {@link HeadscaleAclCompiler} (pure, always present) + the
 *       {@link HeadscaleAclReconciler} ({@code @Scheduled}, leader-gated) are ALWAYS wired — but
 *       in the default disabled mode the reconciler pushes through the Noop client, so the loop
 *       compiles + diffs every tick yet mutates NOTHING. The {@link LeaderElection} bean is the
 *       SAME single-writer primitive the suspension/games loops use.</li>
 * </ul>
 *
 * The WebClient is built LAZILY from the injected builder so a missing/unreachable headscale
 * URL never fails BFF boot; the real client is dialled only on the enabled path.
 */
@Configuration(proxyBeanMethods = false)
@EnableConfigurationProperties(HeadscaleAclProperties.class)
public class HeadscaleAclConfig {

    /** Cluster-less default — used whenever the real push client is not enabled. */
    @Bean
    @ConditionalOnProperty(name = "app.registry.headscale-acl.enabled", havingValue = "false",
            matchIfMissing = true)
    HeadscalePolicyClient noopHeadscalePolicyClient() {
        return new NoopHeadscalePolicyClient();
    }

    /** The REAL WebClient policy client — wired ONLY when the push leg is explicitly enabled. */
    @Bean
    @ConditionalOnProperty(name = "app.registry.headscale-acl.enabled", havingValue = "true")
    HeadscalePolicyClient webClientHeadscalePolicyClient(WebClient.Builder builder,
                                                         HeadscaleAclProperties props,
                                                         ObjectMapper mapper) {
        WebClient http = builder.clone().baseUrl(props.getBaseUrl()).build();
        return new WebClientHeadscalePolicyClient(http, props.getApiKey(), props.getTimeoutMs(), mapper);
    }

    @Bean
    HeadscaleAclCompiler headscaleAclCompiler(ObjectMapper mapper) {
        return new HeadscaleAclCompiler(mapper);
    }

    @Bean
    HeadscaleAclReconciler headscaleAclReconciler(DeviceRegistryExportService exportService,
                                                  HeadscaleAclCompiler compiler,
                                                  HeadscalePolicyClient policyClient,
                                                  LeaderElection leader,
                                                  HeadscaleAclProperties props,
                                                  @Value("${app.registry.headscale-acl.mesh-id:mesh_default}")
                                                  String meshId) {
        return new HeadscaleAclReconciler(exportService, compiler, policyClient, leader,
                props.getMeshId() != null ? props.getMeshId() : meshId);
    }
}
