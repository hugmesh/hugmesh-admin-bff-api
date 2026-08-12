package net.hugmesh.adminbff.locallogin;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Wires the {@link LocalSecretVerifier} for the passwordless local-secrets login. Gated behind
 * {@code app.local-login.enabled} (DEFAULT false) so the endpoint {@code /bff/login/local}
 * SHIPS DARK: with the bean absent, {@code AuthController} injects
 * {@code @Nullable LocalSecretVerifier = null} and the endpoint 401s (fail-closed) — there is NO
 * local-login trust surface until an operator explicitly enables it AND points it at a Casdoor
 * that permits the resource-owner-password grant for the admin-bff application.
 *
 * <p>Endpoint + credentials default off the SAME {@code casdoor.admin.*} env the write client
 * uses ({@code base-url}, {@code client-id}, {@code client-secret}), so a deployment that already
 * configured the Casdoor admin client only needs to flip {@code APP_LOCAL_LOGIN_ENABLED=true}.
 * The {@code token-path} is Casdoor's standard OAuth2 token endpoint.
 */
@Configuration
public class LocalLoginConfig {

    @Bean
    @ConditionalOnProperty(name = "app.local-login.enabled", havingValue = "true")
    public LocalSecretVerifier localSecretVerifier(
            @Value("${app.local-login.casdoor-base-url:${casdoor.admin.base-url:http://casdoor.hugmesh-pki.svc.cluster.local:8000}}")
            String casdoorBaseUrl,
            @Value("${app.local-login.token-path:/api/login/oauth/access_token}") String tokenPath,
            @Value("${app.local-login.client-id:${casdoor.admin.client-id:app-admin-bff}}") String clientId,
            @Value("${app.local-login.client-secret:${casdoor.admin.client-secret:}}") String clientSecret) {
        return new LocalSecretVerifier(casdoorBaseUrl, tokenPath, clientId, clientSecret);
    }
}
