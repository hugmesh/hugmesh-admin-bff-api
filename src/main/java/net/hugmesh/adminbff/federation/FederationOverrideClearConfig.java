package net.hugmesh.adminbff.federation;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.MediaType;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.reactive.function.BodyInserters;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Supplier;

/**
 * Wires the {@link FederationOverrideClearClient} the {@code SuspensionExpiryAction}
 * calls at PROFILE-scope expiry — a SUPERADMIN-service WebClient over
 * federation-api's {@code /api/federation/overrides/clear-source}.
 *
 * <p><b>GATED STUB-SEAM (mirrors {@code UserBffNotificationConfig} /
 * {@code GatewayRevocationClient}).</b> The client bean is ALWAYS present (so the
 * expiry action injects it non-null) but real calls are gated by
 * {@code federation-api.override-clear.enabled} (default {@code false}) so a
 * federation-less dev/test/CI run boots clean — with the gate off the client returns
 * {@link Mono#empty()} without a call. The in-cluster deployment flips
 * {@code FEDERATION_API_OVERRIDE_CLEAR_ENABLED=true} (and supplies the systems-Casdoor
 * service credentials) once federation-api's clear-source endpoint is reachable —
 * config-only, no code change.
 *
 * <h3>Service bearer — reused VERBATIM from the platform pattern</h3>
 * The clear-source endpoint is {@code hasAnyRole('ADMIN','SUPERADMIN')} and
 * domain-scoped on the ISSUER, so this caller presents a Casdoor SUPERADMIN service
 * JWT minted via the OAuth2 {@code client_credentials} grant against hugmesh.net
 * Casdoor — the SAME mechanism + the SAME
 * {@code app.casdoor.systems.{base-url,client-id,client-secret}} credentials
 * {@code UserBffNotificationConfig} uses to mint its ROLE_SERVICE token. The token is
 * cached and re-minted shortly before expiry. When the credentials are absent (a
 * gate-off dev/test run) the supplier is never invoked (the client short-circuits on
 * the disabled gate first), so nothing breaks.
 */
@Configuration(proxyBeanMethods = false)
public class FederationOverrideClearConfig {

    /** Re-mint this long before stated expiry so a call never races the clock. */
    private static final Duration EXPIRY_SKEW = Duration.ofSeconds(60);
    /** Fallback lifetime if Casdoor omits expires_in. */
    private static final Duration DEFAULT_TTL = Duration.ofMinutes(30);

    @Bean
    public FederationOverrideClearClient federationOverrideClearClient(
            WebClient.Builder builder,
            @Value("${federation-api.override-clear.enabled:false}") boolean enabled,
            @Value("${federation-api.base-url:http://hugmesh-federation-api.hugmesh-backend.svc.cluster.local:8080}")
            String baseUrl,
            @Value("${app.casdoor.systems.base-url:}") String casdoorBaseUrl,
            @Value("${app.casdoor.systems.client-id:}") String clientId,
            @Value("${app.casdoor.systems.client-secret:}") String clientSecret) {

        WebClient federation = builder.clone().baseUrl(baseUrl).build();
        WebClient casdoor = builder.clone().baseUrl(casdoorBaseUrl).build();
        Supplier<Mono<String>> tokenSupplier =
                serviceTokenSupplier(casdoor, clientId, clientSecret);
        return new FederationOverrideClearClient(federation, enabled, tokenSupplier);
    }

    /**
     * A caching client-credentials token supplier (identical shape to
     * {@code UserBffNotificationConfig.serviceTokenSupplier} /
     * hugmesh-actions' {@code FederationUsernameClientConfig.serviceTokenSupplier}).
     * Holds the last minted token + the instant it should be considered stale, and
     * re-mints only when stale.
     */
    static Supplier<Mono<String>> serviceTokenSupplier(WebClient casdoor, String clientId, String clientSecret) {
        final AtomicReference<Cached> cache = new AtomicReference<>(null);
        return () -> Mono.defer(() -> {
            Cached c = cache.get();
            if (c != null && Instant.now().isBefore(c.staleAt())) {
                return Mono.just(c.token());
            }
            return mint(casdoor, clientId, clientSecret, cache);
        });
    }

    private static Mono<String> mint(WebClient casdoor, String clientId, String clientSecret,
                                     AtomicReference<Cached> cache) {
        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.add("grant_type", "client_credentials");
        form.add("client_id", clientId);
        form.add("client_secret", clientSecret);
        return casdoor.post()
                .uri("/api/login/oauth/access_token")
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .body(BodyInserters.fromFormData(form))
                .retrieve()
                .bodyToMono(MAP_TYPE)
                // Extract the access_token, compute TTL from expires_in, and cache it.
                .flatMap(json -> extractAndCacheToken(json, cache));
    }

    /** Extract access_token + TTL from the Casdoor token response, populate the cache, and return the token. */
    private static Mono<String> extractAndCacheToken(Map<String, Object> json,
                                                      AtomicReference<Cached> cache) {
        Object at = json.get("access_token");
        if (!(at instanceof String s) || s.isBlank()) {
            return Mono.error(new IllegalStateException("casdoor token mint returned no access_token"));
        }
        Object exp = json.get("expires_in");
        long expiresIn = exp instanceof Number num ? num.longValue() : 0L;
        Duration ttl = expiresIn > 0 ? Duration.ofSeconds(expiresIn) : DEFAULT_TTL;
        cache.set(new Cached(s, Instant.now().plus(ttl).minus(EXPIRY_SKEW)));
        return Mono.just(s);
    }

    @SuppressWarnings("unchecked")
    private static final Class<Map<String, Object>> MAP_TYPE =
            (Class<Map<String, Object>>) (Class<?>) Map.class;

    private record Cached(String token, Instant staleAt) { }
}
