package systems.hugmesh.adminbff.federation;

import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.reactive.function.client.WebClient;

/**
 * Wires the {@link FederationApiClient} on a reactive {@link WebClient} pointed at the
 * in-cluster hugmesh-federation-api with the caller's-bearer forwarding filter
 * (mirrors the mod-bff {@code FederationApiConfig}). The base URL has a sensible
 * in-cluster default ({@code federation-api.base-url}) so the BFF boots without extra
 * config in the cluster, and is overridable per env — the contract is NOT to hardcode
 * without a default.
 *
 * <p>The {@link BearerForwardingFilter} forwards the caller's validated Casdoor JWT so
 * federation-api authorises the {@code /decide} as the original ADMIN (its own
 * {@code @PreAuthorize('hasAnyRole ADMIN,SUPERADMIN')} + per-domain scope), giving
 * defence-in-depth on top of the admin-bff's own method-security + per-domain
 * predicate — and, for a native-login ADMIN, attempts a best-effort custody exchange
 * (see {@link SessionExchangeService}) so the SAME defence-in-depth check applies
 * regardless of whether the caller authenticated via a Casdoor JWT or a {@code bff_}
 * session.
 */
@Configuration(proxyBeanMethods = false)
public class FederationApiConfig {

    @Bean
    WebClient federationWebClient(
            WebClient.Builder builder,
            @Value("${federation-api.base-url:http://hugmesh-federation-api.hugmesh-backend.svc.cluster.local:8080}")
            String baseUrl,
            ObjectProvider<SessionExchangeService> sessionExchangeServiceProvider) {
        return builder.clone()
                .baseUrl(baseUrl)
                .filter(BearerForwardingFilter.forwardCallerToken(sessionExchangeServiceProvider))
                .build();
    }

    @Bean
    FederationApiClient federationApiClient(WebClient federationWebClient) {
        return new FederationApiClient(federationWebClient);
    }
}
