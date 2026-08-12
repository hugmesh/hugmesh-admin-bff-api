package net.hugmesh.adminbff.servicecatalog.federation;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Wires the {@link FederationModuleClient} the Service-Store FEDERATE leg uses. Mirrors
 * {@link net.hugmesh.adminbff.argocd.ArgoCdConfig} EXACTLY: ONE flag
 * ({@code app.appstore.federation.enabled}, default false) gates two mutually-exclusive beans so
 * EXACTLY ONE is registered in every mode.
 *
 * <ul>
 *   <li>flag false (DEFAULT) → {@link NoopFederationModuleClient}: the federate leg ships dark —
 *       the flow runs its full sequence against a no-op federation seam, so a dev/test/CI run
 *       boots clean and dials no federation-api;</li>
 *   <li>flag true → {@link RestFederationModuleClient}: the real federation-api admin client
 *       (Bearer token), for the in-cluster deployment that has opted the federate leg in.</li>
 * </ul>
 *
 * <p>Endpoint + token come from {@code app.appstore.federation.*} (env-driven). NO secret in git —
 * the token defaults empty and is injected by the deployment (it must be a Casdoor JWT carrying
 * ROLE_SUPERADMIN, per federation-api's admin-API guard).
 */
@Configuration(proxyBeanMethods = false)
public class FederationModuleClientConfig {

    /** Ships-dark default — used whenever the federate leg is not enabled. */
    @Bean
    @ConditionalOnProperty(name = "app.appstore.federation.enabled", havingValue = "false",
            matchIfMissing = true)
    FederationModuleClient noopFederationModuleClient() {
        return new NoopFederationModuleClient();
    }

    /** The REAL federation-api admin client — wired ONLY when the federate leg is enabled. */
    @Bean
    @ConditionalOnProperty(name = "app.appstore.federation.enabled", havingValue = "true")
    FederationModuleClient restFederationModuleClient(
            @Value("${app.appstore.federation.base-url:http://hugmesh-federation-api.hugmesh-backend.svc.cluster.local:8080}")
                    String baseUrl,
            @Value("${app.appstore.federation.auth-token:}") String authToken) {
        return new RestFederationModuleClient(baseUrl, authToken);
    }
}
