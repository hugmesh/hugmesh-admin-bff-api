package net.hugmesh.adminbff.charactermoderation;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

import java.time.Duration;
import java.util.List;
import java.util.function.Supplier;

/**
 * Reactive ROLE_SERVICE client over hugmesh-federation-api's resolved-findings READ
 * endpoint (#71), the SOURCE leg of the moderation→activation loop:
 *
 * <pre>GET {federation}/api/federation/findings/resolved
 *      ?surface=&lt;character-part|character-sticker&gt;&amp;sinceId=&lt;Long&gt;&amp;limit=&lt;&le;500&gt;</pre>
 *
 * <p>Returns the resolved findings with {@code id > sinceId} in {@code id ASC} order (a
 * STRICT cursor), each a {@link ResolvedFindingDto}. The {@link FindingActivationReconciler}
 * polls this per surface from its persisted watermark.
 *
 * <h3>Auth — ROLE_SERVICE service bearer (reused VERBATIM from the platform pattern)</h3>
 * The endpoint is {@code hasAnyRole('SERVICE','ADMIN','SUPERADMIN')}. This poll runs in a
 * SYSTEM / SCHEDULED context (no human request, no forwardable caller JWT), so it presents
 * a Casdoor SERVICE-account JWT minted via the OAuth2 {@code client_credentials} grant
 * against hugmesh.net Casdoor — the SAME mechanism + the SAME
 * {@code app.casdoor.platform.{base-url,client-id,client-secret}} credentials the
 * {@code UserBffNotificationConfig} / {@code FederationOverrideClearConfig} service clients
 * use. The token {@link Supplier} caches + re-mints (see
 * {@link FindingActivationReconcilerConfig}); this client just asks for a current bearer
 * per poll.
 *
 * <h3>GATED, best-effort (matches {@code FederationOverrideClearClient})</h3>
 * The bean is ALWAYS injected non-null but real calls are gated by
 * {@code character-moderation.reconciler.enabled} (default {@code false}) so a
 * federation-less dev/test/CI run boots clean — with the gate off {@link #fetchResolved}
 * returns an EMPTY list WITHOUT a network call (the reconciler then no-ops, the cursor is
 * untouched). On a real call any transport/status error is mapped to a Reactor ERROR so the
 * reconciler's per-surface handler swallows it and RETRIES next tick (it must NOT advance
 * the cursor on a failed poll). The caller never sees an exception escape its tick.
 */
public class FederationResolvedFindingsClient {

    private static final Logger log = LoggerFactory.getLogger(FederationResolvedFindingsClient.class);

    /** Bound the poll so a slow federation-api never stalls a reconcile tick. */
    private static final Duration CALL_TIMEOUT = Duration.ofSeconds(10);

    /** The federation resolved-findings contract path (#71). */
    static final String PATH = "/api/federation/findings/resolved";

    /** Hard contract ceiling for the page size (the endpoint caps at 500). */
    static final int MAX_LIMIT = 500;

    private final WebClient http;
    private final boolean enabled;
    private final Supplier<Mono<String>> serviceToken;

    /**
     * @param http         WebClient pre-pointed at federation-api's base URL.
     * @param enabled      whether to make real calls (false short-circuits to an empty page).
     * @param serviceToken supplies a current Casdoor SERVICE bearer (cached / re-minted).
     */
    public FederationResolvedFindingsClient(WebClient http, boolean enabled,
                                            Supplier<Mono<String>> serviceToken) {
        this.http = http;
        this.enabled = enabled;
        this.serviceToken = serviceToken;
    }

    public boolean enabled() {
        return enabled;
    }

    /**
     * GET one page of resolved findings for a surface with {@code id > sinceId}, id ASC,
     * capped at {@code limit} (clamped to {@link #MAX_LIMIT}). With the gate OFF returns an
     * EMPTY list without a call. On a real call a transport/status error PROPAGATES as a
     * Reactor error (so the reconciler retries the surface next tick WITHOUT advancing the
     * cursor) — a failed poll must never look like "no findings".
     *
     * @param surface {@code character-part} | {@code character-sticker}
     * @param sinceId strict lower-bound cursor; {@code null} (cold start) sends 0
     * @param limit   page size, clamped to {@link #MAX_LIMIT}
     */
    public Mono<List<ResolvedFindingDto>> fetchResolved(String surface, Long sinceId, int limit) {
        if (!enabled) {
            log.debug("[char-mod-reconcile] federation gate OFF; empty page (no call) surface={}", surface);
            return Mono.just(List.of());
        }
        long since = sinceId == null ? 0L : sinceId;
        int cappedLimit = Math.min(Math.max(1, limit), MAX_LIMIT);
        return serviceToken.get()
                .flatMap(token -> http.get()
                        .uri(uri -> uri.path(PATH)
                                .queryParam("surface", surface)
                                .queryParam("sinceId", since)
                                .queryParam("limit", cappedLimit)
                                .build())
                        // Reused VERBATIM from the platform ROLE_SERVICE pattern:
                        // Authorization: Bearer <Casdoor client_credentials JWT>.
                        .headers(h -> h.setBearerAuth(token))
                        .retrieve()
                        .bodyToFlux(ResolvedFindingDto.class)
                        .collectList())
                .timeout(CALL_TIMEOUT)
                .doOnNext(page -> log.debug("[char-mod-reconcile] fetched {} resolved finding(s) "
                        + "surface={} sinceId={}", page.size(), surface, since));
                // NB: NO onErrorResume here — a failed poll must propagate so the reconciler
                // skips the surface this tick and retries (it must not advance on a failure).
                // collectList() always emits (an empty list for an empty 200 array), so there
                // is no empty-completion case to guard.
    }
}
