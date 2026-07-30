package systems.hugmesh.{{APP_SLUG}};

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;

/**
 * Minimal Casdoor-aware OAuth2 resource-server security in the platform BFF
 * convention (cribbed from the admin-bff-api exemplar, with the multi-issuer /
 * cookie-session machinery left out until this service needs it):
 *
 * <ul>
 *   <li>{@code /actuator/health} + probe subpaths are PUBLIC — k8s liveness/
 *       readiness and the compose healthcheck must never need a token;</li>
 *   <li>EVERYTHING else is {@code authenticated()}: a valid Casdoor JWT
 *       (issuer/JWKS from {@code CASDOOR_ISSUER_URI}/{@code CASDOOR_JWKS_URI}
 *       env, see application.yml) is required — the fe-gateway's route rules are
 *       defence-in-depth ABOVE this, never a substitute for it;</li>
 *   <li>CSRF is disabled: this is a stateless Bearer-JWT API (no cookie session
 *       minted here). The cookie-mode + CSRF pairing the fleet BFFs gate behind
 *       {@code app.auth.cookie-session.enabled} arrives only WITH a cookie
 *       mint, never before it.</li>
 * </ul>
 */
@Configuration
@EnableWebFluxSecurity
public class SecurityConfig {

    @Bean
    public SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http) {
        return http
                .csrf(ServerHttpSecurity.CsrfSpec::disable)
                .authorizeExchange(exchanges -> exchanges
                        .pathMatchers("/actuator/health", "/actuator/health/**").permitAll()
                        .anyExchange().authenticated())
                .oauth2ResourceServer(oauth2 -> oauth2.jwt(Customizer.withDefaults()))
                .build();
    }
}
