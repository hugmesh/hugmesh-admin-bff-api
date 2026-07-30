package systems.hugmesh.adminbff.phone;

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.reactive.function.client.WebClient;

/**
 * Wires the phone-lock enforcement legs (Headwind DPC, headscale mesh-deny, and the
 * changeset-307 Azure Intune co-equal DPC leg). Mirrors {@link
 * systems.hugmesh.adminbff.device.HeadscaleAclConfig} EXACTLY: each leg is a pair of beans
 * gated by the SAME property with mutually-exclusive values, so EXACTLY ONE bean per leg is
 * registered in every mode (a {@code @ConditionalOnMissingBean} no-op cannot guarantee
 * uniqueness within one {@code @Configuration}). {@link DefaultPhoneLockEnforcer} then injects
 * the resulting {@code List<PhoneLockLeg>} (one per leg) and aggregates only the legs whose
 * {@code appliesTo(device)} matches the device's reported MDM provider.
 *
 * <p>The WebClient is built LAZILY from the injected builder so a missing/unreachable
 * Headwind/headscale URL never fails BFF boot; the real client is dialled only on the enabled
 * path. Default (both flags off) &rarr; both no-op legs &rarr; the enforcer degrades with the
 * documented console reason, and the lock/unlock control-plane state is still authoritative.
 */
@Configuration(proxyBeanMethods = false)
@EnableConfigurationProperties(PhoneLockProperties.class)
public class PhoneLockConfig {

    // ── Headwind device-owner DPC lock leg ───────────────────────────────────────

    /** Cluster-less default — used whenever the real Headwind leg is not enabled. */
    @Bean
    @ConditionalOnProperty(name = "app.phone-lock.headwind.enabled", havingValue = "false",
            matchIfMissing = true)
    PhoneLockLeg noopHeadwindDpcLockClient() {
        return new NoopHeadwindDpcLockClient();
    }

    /** The REAL Headwind DPC leg — wired ONLY when the leg is explicitly enabled. */
    @Bean
    @ConditionalOnProperty(name = "app.phone-lock.headwind.enabled", havingValue = "true")
    PhoneLockLeg headwindDpcLockClient(WebClient.Builder builder, PhoneLockProperties props) {
        WebClient http = builder.clone().baseUrl(props.getHeadwind().getBaseUrl()).build();
        return new HeadwindDpcLockClient(http, props.getHeadwind().getApiKey(),
                props.getHeadwind().getTimeoutMs());
    }

    // ── headscale ACL phone-deny leg ─────────────────────────────────────────────

    /** Cluster-less default — used whenever the real mesh-deny leg is not enabled. */
    @Bean
    @ConditionalOnProperty(name = "app.phone-lock.mesh-deny.enabled", havingValue = "false",
            matchIfMissing = true)
    PhoneLockLeg noopPhoneMeshDenyClient() {
        return new NoopPhoneMeshDenyClient();
    }

    /** The REAL headscale phone-deny leg — wired ONLY when the leg is explicitly enabled. */
    @Bean
    @ConditionalOnProperty(name = "app.phone-lock.mesh-deny.enabled", havingValue = "true")
    PhoneLockLeg phoneMeshDenyClient(WebClient.Builder builder, PhoneLockProperties props) {
        WebClient http = builder.clone().baseUrl(props.getMeshDeny().getBaseUrl()).build();
        return new PhoneMeshDenyClient(http, props.getMeshDeny().getApiKey(),
                props.getMeshDeny().getTimeoutMs());
    }

    // ── Azure Intune (Graph) co-equal DPC leg (changeset 307) ────────────────────

    /** Cluster-less default — used whenever the real Intune leg is not enabled (the default;
     *  Intune ships dark so a deployment stays sovereign until it opts in). */
    @Bean
    @ConditionalOnProperty(name = "app.phone-lock.azure-intune.enabled", havingValue = "false",
            matchIfMissing = true)
    PhoneLockLeg noopAzureIntuneLockClient() {
        return new NoopAzureIntuneLockClient();
    }

    /** The REAL Intune leg — wired ONLY when explicitly enabled. The WebClient carries NO base
     *  URL: the token (Entra) and remoteLock (Graph) hosts differ, so the leg dials absolute
     *  URIs built from the two configured base URLs. */
    @Bean
    @ConditionalOnProperty(name = "app.phone-lock.azure-intune.enabled", havingValue = "true")
    PhoneLockLeg azureIntuneLockClient(WebClient.Builder builder, PhoneLockProperties props) {
        PhoneLockProperties.AzureIntune ai = props.getAzureIntune();
        WebClient http = builder.clone().build();
        return new AzureIntuneLockClient(http, ai.getTenantId(), ai.getClientId(),
                ai.getClientSecret(), ai.getGraphBaseUrl(), ai.getAuthBaseUrl(),
                ai.getTimeoutMs());
    }
}
