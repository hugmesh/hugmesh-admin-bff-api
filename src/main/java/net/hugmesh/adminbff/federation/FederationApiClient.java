package net.hugmesh.adminbff.federation;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

/**
 * Reactive WebClient client of hugmesh-federation-api — the admin-bff is a CLIENT
 * of federation-api, never the other way round (mirrors the mod-bff
 * {@code FederationApiClient}). The base URL has a sensible in-cluster default
 * ({@code federation-api.base-url}) so the BFF boots without extra config in the
 * cluster, and is overridable per env (never hardcoded without a default). Every call
 * carries the CALLER's Casdoor JWT via {@link BearerForwardingFilter} wired into the
 * injected {@link WebClient}, so federation-api's own
 * {@code @PreAuthorize("hasAnyRole('ADMIN','SUPERADMIN')")} + its per-domain scope see
 * the original admin.
 *
 * <p>Endpoint used (matched field-for-field to the federation-api
 * {@code ModerationController}):
 * <ul>
 *   <li>{@code POST /api/federation/moderation/{id}/decide?approve=<bool>} — an ADMIN
 *       approves / denies a referred moderation request. The admin-ui appeals console
 *       wires to the admin-bff's own {@code /bff/admin/moderation/{id}/decide}, which
 *       proxies here.</li>
 * </ul>
 */
public class FederationApiClient {

    private static final Logger log = LoggerFactory.getLogger(FederationApiClient.class);

    private final WebClient http;

    public FederationApiClient(WebClient http) {
        this.http = http;
    }

    /**
     * Decide (approve / deny) a moderation request. federation-api derives the
     * adminDecider from the forwarded JWT subject and scopes the row to the caller's
     * domain, so only {@code id} + {@code approve} are sent. Returns the updated
     * moderation row (status flipped to {@code approved}/{@code denied}).
     */
    public Mono<ModerationDecisionDto> decide(long id, boolean approve) {
        return http.post()
                .uri(uri -> uri.path("/api/federation/moderation/{id}/decide")
                        .queryParam("approve", approve)
                        .build(id))
                .retrieve()
                .bodyToMono(ModerationDecisionDto.class)
                .doOnSuccess(r -> log.info("[federation] decided moderation request {} approve={}", id, approve));
    }
}
