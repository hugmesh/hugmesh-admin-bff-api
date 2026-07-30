package systems.hugmesh.adminbff.charactermoderation;

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
 * Wires the two ROLE_SERVICE clients the {@link FindingActivationReconciler} drives — the
 * federation resolved-findings READ ({@link FederationResolvedFindingsClient}, #71) and the
 * user-bff character moderation SINK ({@link UserBffCharacterModerationClient}, #87).
 *
 * <p><b>GATED STUB-SEAM (mirrors {@code UserBffNotificationConfig} /
 * {@code FederationOverrideClearConfig}).</b> Both client beans are ALWAYS present (so the
 * reconciler injects them non-null) but real calls are gated by ONE flag,
 * {@code character-moderation.reconciler.enabled} (default {@code false}), so a
 * federation/user-bff-less dev/test/CI run boots clean — with the gate off the federation
 * read returns an empty page (no advance) and the sink push returns FAILED (no advance), so
 * the loop is inert + safe. The in-cluster deployment flips
 * {@code CHARACTER_MODERATION_RECONCILER_ENABLED=true} once BOTH contracts are reachable —
 * config-only, no code change.
 *
 * <h3>Base URLs — reused from the existing properties</h3>
 * {@code federation-api.base-url} (the SAME property {@code FederationOverrideClearConfig}
 * reads) and {@code notification.user-bff.base-url} (the SAME property
 * {@code UserBffNotificationConfig} reads), both with their in-cluster defaults — so this
 * feature adds no NEW endpoint config beyond the single enable flag.
 *
 * <h3>Service bearer — reused VERBATIM from the platform pattern</h3>
 * Both endpoints are ROLE_SERVICE-gated; both clients present a Casdoor SERVICE JWT minted
 * via the OAuth2 {@code client_credentials} grant against hugmesh.systems Casdoor — the
 * SAME mechanism + the SAME {@code app.casdoor.systems.{base-url,client-id,client-secret}}
 * credentials the sibling service clients use. ONE caching supplier is shared by both
 * clients (one token, two call sites). When the credentials are absent (a gate-off
 * dev/test run) the supplier is never invoked (the clients short-circuit on the disabled
 * gate first), so nothing breaks.
 */
@Configuration(proxyBeanMethods = false)
public class FindingActivationReconcilerConfig {

    /** Re-mint this long before stated expiry so a call never races the clock. */
    private static final Duration EXPIRY_SKEW = Duration.ofSeconds(60);
    /** Fallback lifetime if Casdoor omits expires_in. */
    private static final Duration DEFAULT_TTL = Duration.ofMinutes(30);

    @Bean
    public FederationResolvedFindingsClient federationResolvedFindingsClient(
            WebClient.Builder builder,
            @Value("${character-moderation.reconciler.enabled:false}") boolean enabled,
            @Value("${federation-api.base-url:http://hugmesh-federation-api.hugmesh-backend.svc.cluster.local:8080}")
            String federationBaseUrl,
            @Value("${app.casdoor.systems.base-url:}") String casdoorBaseUrl,
            @Value("${app.casdoor.systems.client-id:}") String clientId,
            @Value("${app.casdoor.systems.client-secret:}") String clientSecret) {

        WebClient federation = builder.clone().baseUrl(federationBaseUrl).build();
        WebClient casdoor = builder.clone().baseUrl(casdoorBaseUrl).build();
        Supplier<Mono<String>> tokenSupplier =
                serviceTokenSupplier(casdoor, clientId, clientSecret);
        return new FederationResolvedFindingsClient(federation, enabled, tokenSupplier);
    }

    @Bean
    public UserBffCharacterModerationClient userBffCharacterModerationClient(
            WebClient.Builder builder,
            @Value("${character-moderation.reconciler.enabled:false}") boolean enabled,
            @Value("${notification.user-bff.base-url:http://hugmesh-user-bff-api.hugmesh-backend.svc.cluster.local:8080}")
            String userBffBaseUrl,
            @Value("${app.casdoor.systems.base-url:}") String casdoorBaseUrl,
            @Value("${app.casdoor.systems.client-id:}") String clientId,
            @Value("${app.casdoor.systems.client-secret:}") String clientSecret) {

        WebClient userBff = builder.clone().baseUrl(userBffBaseUrl).build();
        WebClient casdoor = builder.clone().baseUrl(casdoorBaseUrl).build();
        Supplier<Mono<String>> tokenSupplier =
                serviceTokenSupplier(casdoor, clientId, clientSecret);
        return new UserBffCharacterModerationClient(userBff, enabled, tokenSupplier);
    }

    /**
     * A caching client-credentials token supplier (identical shape to
     * {@code UserBffNotificationConfig.serviceTokenSupplier} /
     * {@code FederationOverrideClearConfig.serviceTokenSupplier}). Holds the last minted
     * token + the instant it should be considered stale, and re-mints only when stale.
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
