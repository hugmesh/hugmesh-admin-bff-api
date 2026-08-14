package net.hugmesh.adminbff.federation;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.MediaType;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.function.Supplier;

/**
 * Best-effort, GATED client over hugmesh-federation-api's
 * {@code POST /api/federation/overrides/clear-source} (the suspension-clear rebuild
 * path). It re-arms — stamps {@code cleared_at} on — every ACTIVE
 * {@code federation_override} row whose {@code reason} (source tag) equals the given
 * source, so the manifest read path stops suppressing the suspended owner's modules
 * (they return on the next render).
 *
 * <h3>Why this exists (the missing restore leg)</h3>
 * When a PROFILE-scope timed suspension is APPLIED, the federation side writes a
 * {@code scope=user} kill override tagged {@code reason='access_suspension:<id>'}; the
 * homeserver re-activate + Casdoor role-restore legs already fire at expiry, but the
 * federation override was previously left armed (documented as a follow-up seam in
 * {@code SuspensionExpiryAction}). This client closes that loop: at PROFILE-scope
 * expiry the expiry action calls {@link #clearSource} with {@code access_suspension:<id>}
 * and the federation row is re-armed.
 *
 * <h3>Auth — SUPERADMIN service bearer (reused VERBATIM from the platform pattern)</h3>
 * The clear-source endpoint is {@code @PreAuthorize("hasAnyRole('ADMIN','SUPERADMIN')")}
 * and DOMAIN-SCOPED: federation derives the caller's domain from the validated token
 * ISSUER (never a body field) and a per-domain admin re-arms ONLY rows in their own
 * brand. The expiry action runs in a SYSTEM / SCHEDULED context (no human request, no
 * forwardable caller JWT) and is the single cross-brand clock, so it presents a Casdoor
 * SERVICE-account JWT minted via the OAuth2 {@code client_credentials} grant against
 * hugmesh.net Casdoor — the SAME mechanism + the SAME
 * {@code app.casdoor.systems.{base-url,client-id,client-secret}} credentials the
 * {@code UserBffNotificationConfig} / hugmesh-actions service clients use. That
 * service account carries the cross-domain SUPERADMIN authority (the infra control
 * plane), so the domain-scoped endpoint ACCEPTS the call for the affected user's domain
 * regardless of which brand minted the original suspension — and because the source tag
 * is a globally-unique {@code access_suspension:<UUID>}, a cross-domain clear-by-source
 * only ever matches that one user's row. The token {@link Supplier} caches + re-mints
 * (see {@link FederationOverrideClearConfig}); this client just asks for a current
 * bearer per call.
 *
 * <h3>GATED, best-effort (matches {@link net.hugmesh.authcore.provision.GatewayRevocationClient})</h3>
 * The bean is ALWAYS injected non-null but real calls are gated by
 * {@code federation-api.override-clear.enabled} (default {@code false}) so a
 * federation-less dev/test/CI run boots clean — with the gate off
 * {@link #clearSource} logs and returns {@link Mono#empty()} WITHOUT a network call.
 * On a real call any transport/status error is LOGGED and swallowed: the authoritative
 * restore state is the {@code access_suspension} row (already CASed to {@code restored})
 * and the federation override read path is itself idempotent/self-healing, so a failed
 * clear here never reverts the row to a silent permanent suppression. The caller MUST
 * NOT propagate the error.
 */
public class FederationOverrideClearClient {

    private static final Logger log = LoggerFactory.getLogger(FederationOverrideClearClient.class);

    /** Bound the call so a slow federation-api never stalls an expiry tick. */
    private static final Duration CALL_TIMEOUT = Duration.ofSeconds(5);

    /** The federation clear-by-source contract path. */
    static final String PATH = "/api/federation/overrides/clear-source";

    private final WebClient http;
    private final boolean enabled;
    private final Supplier<Mono<String>> serviceToken;

    /**
     * @param http         WebClient pre-pointed at federation-api's base URL.
     * @param enabled      whether to make real calls (false short-circuits to no-op).
     * @param serviceToken supplies a current Casdoor SUPERADMIN service bearer
     *                     (cached / re-minted).
     */
    public FederationOverrideClearClient(WebClient http, boolean enabled,
                                         Supplier<Mono<String>> serviceToken) {
        this.http = http;
        this.enabled = enabled;
        this.serviceToken = serviceToken;
    }

    public boolean enabled() {
        return enabled;
    }

    /**
     * POST the clear-by-source request to federation-api. Best-effort: errors are
     * swallowed (logged). A blank source is a no-op (the federation endpoint would
     * 400, and there is nothing to clear).
     *
     * @param source the SOURCE tag whose override row(s) to re-arm, e.g.
     *               {@code access_suspension:<id>}
     */
    public Mono<Void> clearSource(String source) {
        if (source == null || source.isBlank()) {
            return Mono.empty();
        }
        if (!enabled) {
            log.debug("[federation-override-clear] STUB (override-clear.enabled=false): clear source={}", source);
            return Mono.empty();
        }
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("source", source);
        return serviceToken.get()
                .flatMap(token -> http.post()
                        .uri(PATH)
                        .contentType(MediaType.APPLICATION_JSON)
                        // SUPERADMIN service bearer — the domain-scoped endpoint accepts
                        // it for the affected user's domain (cross-brand infra control plane).
                        .headers(h -> h.setBearerAuth(token))
                        .bodyValue(body)
                        .retrieve()
                        .bodyToMono(Long.class))
                .timeout(CALL_TIMEOUT)
                .doOnNext(cleared -> log.info(
                        "[federation-override-clear] cleared {} federation override row(s) for source={}",
                        cleared, source))
                .then()
                .onErrorResume(e -> {
                    log.warn("[federation-override-clear] best-effort clearSource({}) failed "
                            + "(restore still in DB; read path self-heals): {}", source, e.toString());
                    return Mono.empty();
                });
    }
}
