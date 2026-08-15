package net.hugmesh.adminbff.device;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.reactive.function.client.WebClient;
import net.hugmesh.adminbff.lease.LeaderElection;

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
        requireDbPolicyMode(props);
        WebClient http = builder.clone().baseUrl(props.getBaseUrl()).build();
        return new WebClientHeadscalePolicyClient(http, props.getApiKey(), props.getTimeoutMs(), mapper);
    }

    /**
     * THE SINGLE-WRITER GATE. {@code PUT /api/v1/policy} — the only write this leg has — is a
     * DB-policy-mode call; headscale in {@code policy: mode: file} rejects it with 4xx. This
     * fleet ships file mode (hugmesh-generator {@code specs/etc/headscale/config.yaml}) with the
     * node-side {@code gen-headscale-policy.sh} as the writer of {@code policy.hujson}.
     *
     * <p>Without this gate, flipping {@code enabled=true} on the fleet as shipped produces a
     * PERMANENT SILENT NO-OP: every 60 s tick compiles, PUTs, gets a 4xx, logs one WARN line
     * ("degraded — keeping last-good"), and retries forever. Nothing is applied, nothing is
     * obviously broken, and the operator believes Layer-A push is live. So the mismatch is made
     * IMPOSSIBLE TO MISS: the bean refuses to be created and the context fails to start, naming
     * both sides of the mismatch and the decision that has to be made first.
     *
     * <p>Only reached on the enabled path — with the push off (the default) this method never
     * runs and boot is unchanged.
     *
     * @throws IllegalStateException when the declared policy mode is anything but {@code db}
     */
    static void requireDbPolicyMode(HeadscaleAclProperties props) {
        String declared = props.getPolicyMode() == null ? "" : props.getPolicyMode().trim();
        if ("db".equalsIgnoreCase(declared)) {
            return;
        }
        throw new IllegalStateException(
                "[headscale-acl] POLICY-MODE MISMATCH — refusing to wire the Layer-A push client. "
                        + "app.registry.headscale-acl.enabled=true but "
                        + "app.registry.headscale-acl.policy-mode='" + declared + "' (expected 'db'). "
                        + "PUT /api/v1/policy is a DB-POLICY-MODE-ONLY call; headscale in file mode "
                        + "rejects it with 4xx, so an enabled push would be a permanent silent no-op. "
                        + "This fleet ships file mode: hugmesh-generator specs/etc/headscale/config.yaml "
                        + "sets policy.mode=file and specs/usr/sbin/gen-headscale-policy.sh is the single "
                        + "writer of /etc/headscale/policy.hujson (headscale policy set -f). "
                        + "DECIDE THE SINGLE WRITER FIRST: either keep file mode and leave this leg "
                        + "disabled (app.registry.headscale-acl.enabled=false), or move headscale to "
                        + "policy.mode=db AND stop the node-side hugmesh-policy-sync writer, then set "
                        + "app.registry.headscale-acl.policy-mode=db. Two writers against one policy "
                        + "will flap the mesh.");
    }

    @Bean
    HeadscaleAclCompiler headscaleAclCompiler(ObjectMapper mapper, HeadscaleAclProperties props) {
        // mesh-id + ssh-user feed the compiled policy's SUPERADMIN mesh rule (tag:mesh_<id>) and
        // every rule's `users` — both must match what the node side actually forces/renders.
        return new HeadscaleAclCompiler(mapper, props.getMeshId(), props.getSshUser());
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
