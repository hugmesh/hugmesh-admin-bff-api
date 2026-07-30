package systems.hugmesh.adminbff.phone;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Configuration for the two phone-lock ENFORCEMENT legs, bound on {@code app.phone-lock.*}.
 * Both legs ship DARK (disabled) by default: with no leg enabled, a lock/unlock still records
 * its authoritative DB state and the {@link PhoneLockEnforcer} reports DEGRADED with the
 * documented Headwind-console reason — the control plane is complete, only the real-time
 * device-affecting push is deferred.
 *
 * <ul>
 *   <li>{@link Headwind} — the device-owner DPC lock over the Headwind admin REST surface. Its
 *       real-time delivery to the handset is the MQTT:31000 gap; the token custody is
 *       operator-side.</li>
 *   <li>{@link MeshDeny} — the headscale ACL phone-deny for the phone's tailnet host. Needs
 *       headscale in DB-policy mode + the phone&rarr;node ACL identity.</li>
 *   <li>{@link AzureIntune} — the co-equal cloud DPC leg over Microsoft Graph/Intune
 *       (changeset 307). Ships DARK; enabling it forfeits sovereignty (a Microsoft SaaS
 *       dependency), which is why Headwind stays the default and this is opt-in per deployment.
 *       Secrets (tenant/client/secret) are Vault/ESO-injected placeholders, blank by default —
 *       NEVER inline, NEVER logged, NEVER on argv.</li>
 * </ul>
 * Independent flags so the legs flip on separately (a deployment may cut mesh access long
 * before it can command a device-owner lock, or vice versa; Intune is a distinct provider leg
 * that fires only for an {@code 'azure-intune'} device).
 */
@ConfigurationProperties(prefix = "app.phone-lock")
public class PhoneLockProperties {

    private Headwind headwind = new Headwind();
    private MeshDeny meshDeny = new MeshDeny();
    private AzureIntune azureIntune = new AzureIntune();

    public Headwind getHeadwind() { return headwind; }
    public void setHeadwind(Headwind headwind) { this.headwind = headwind; }

    public MeshDeny getMeshDeny() { return meshDeny; }
    public void setMeshDeny(MeshDeny meshDeny) { this.meshDeny = meshDeny; }

    public AzureIntune getAzureIntune() { return azureIntune; }
    public void setAzureIntune(AzureIntune azureIntune) { this.azureIntune = azureIntune; }

    /** The Headwind device-owner DPC lock leg. */
    public static class Headwind {

        /** Whether to push a real device-owner lock/unlock to the Headwind server. Default
         *  <b>false</b> (ships dark) &rarr; {@link NoopHeadwindDpcLockClient} is wired. */
        private boolean enabled = false;

        /** The Headwind admin REST base URL (only used when {@link #enabled}). */
        private String baseUrl = "http://hmdm.hmdm.svc.cluster.local:8080";

        /** The Headwind admin API key (Vault-injected placeholder; NEVER inline). Blank by
         *  default &rarr; no Authorization header (a recording test exercises the shape). */
        private String apiKey = "";

        /** Per-call timeout (ms) for a lock/unlock command. */
        private long timeoutMs = 8000;

        public boolean isEnabled() { return enabled; }
        public void setEnabled(boolean enabled) { this.enabled = enabled; }

        public String getBaseUrl() { return baseUrl; }
        public void setBaseUrl(String baseUrl) { this.baseUrl = baseUrl; }

        public String getApiKey() { return apiKey; }
        public void setApiKey(String apiKey) { this.apiKey = apiKey; }

        public long getTimeoutMs() { return timeoutMs; }
        public void setTimeoutMs(long timeoutMs) { this.timeoutMs = timeoutMs; }
    }

    /** The headscale ACL phone-deny leg. */
    public static class MeshDeny {

        /** Whether to push a real headscale ACL deny for the phone's tailnet host. Default
         *  <b>false</b> (ships dark) &rarr; {@link NoopPhoneMeshDenyClient} is wired. */
        private boolean enabled = false;

        /** The headscale control-plane API base URL (only used when {@link #enabled}). */
        private String baseUrl = "http://headscale.headscale.svc.cluster.local:8080";

        /** The headscale admin API key (Vault-injected placeholder; NEVER inline). */
        private String apiKey = "";

        /** Per-call timeout (ms) for a deny/re-allow push. */
        private long timeoutMs = 8000;

        public boolean isEnabled() { return enabled; }
        public void setEnabled(boolean enabled) { this.enabled = enabled; }

        public String getBaseUrl() { return baseUrl; }
        public void setBaseUrl(String baseUrl) { this.baseUrl = baseUrl; }

        public String getApiKey() { return apiKey; }
        public void setApiKey(String apiKey) { this.apiKey = apiKey; }

        public long getTimeoutMs() { return timeoutMs; }
        public void setTimeoutMs(long timeoutMs) { this.timeoutMs = timeoutMs; }
    }

    /** The Azure Intune (Microsoft Graph) co-equal cloud DPC leg (changeset 307). */
    public static class AzureIntune {

        /** Whether to push a real Intune remoteLock via Graph. Default <b>false</b> (ships
         *  dark — enabling forfeits sovereignty) &rarr; {@link NoopAzureIntuneLockClient} is
         *  wired. */
        private boolean enabled = false;

        /** The Entra (Azure AD) tenant id the confidential-client app lives in (only used
         *  when {@link #enabled}). */
        private String tenantId = "";

        /** The confidential-client application (client) id (only used when {@link #enabled}). */
        private String clientId = "";

        /** The confidential-client secret (Vault/ESO-injected placeholder; NEVER inline, NEVER
         *  logged, NEVER argv). Blank by default. Rides ONLY the urlencoded token form body. */
        private String clientSecret = "";

        /** The Microsoft Graph base URL. Default v1.0. */
        private String graphBaseUrl = "https://graph.microsoft.com/v1.0";

        /** The Entra OAuth2 authority base URL (the {@code /{tenant}/oauth2/v2.0/token}
         *  endpoint hangs off this). Default the public cloud login host. */
        private String authBaseUrl = "https://login.microsoftonline.com";

        /** Per-call timeout (ms) for the token + remoteLock calls. */
        private long timeoutMs = 8000;

        public boolean isEnabled() { return enabled; }
        public void setEnabled(boolean enabled) { this.enabled = enabled; }

        public String getTenantId() { return tenantId; }
        public void setTenantId(String tenantId) { this.tenantId = tenantId; }

        public String getClientId() { return clientId; }
        public void setClientId(String clientId) { this.clientId = clientId; }

        public String getClientSecret() { return clientSecret; }
        public void setClientSecret(String clientSecret) { this.clientSecret = clientSecret; }

        public String getGraphBaseUrl() { return graphBaseUrl; }
        public void setGraphBaseUrl(String graphBaseUrl) { this.graphBaseUrl = graphBaseUrl; }

        public String getAuthBaseUrl() { return authBaseUrl; }
        public void setAuthBaseUrl(String authBaseUrl) { this.authBaseUrl = authBaseUrl; }

        public long getTimeoutMs() { return timeoutMs; }
        public void setTimeoutMs(long timeoutMs) { this.timeoutMs = timeoutMs; }
    }
}
