package net.hugmesh.adminbff.charactermoderation;

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
 * Reactive ROLE_SERVICE client over user-bff's INTERNAL character moderation SINK (#87),
 * the SINK leg of the moderation→activation loop:
 *
 * <pre>POST {user-bff}/bff/user/internal/character/{parts|stickers}/{id}/moderation
 *      body { status: "ACTIVE"|"REJECTED", findingId, reviewer }</pre>
 *
 * <p>The endpoint is {@code hasRole('SERVICE')} and IDEMPOTENT — it flips ONLY a
 * {@code PENDING} row to ACTIVE/REJECTED, so re-POSTing an already-applied (earlier,
 * already-flipped) row on a retry is a harmless no-op. {@code {id}} is the finding's
 * {@code subjectRef} (the user-bff row id); {@code {parts|stickers}} is selected from the
 * finding surface (character-part → parts, character-sticker → stickers).
 *
 * <h3>Auth (reused VERBATIM from the platform ROLE_SERVICE pattern)</h3>
 * The same Casdoor {@code client_credentials} SERVICE bearer the
 * {@code UserBffNotificationClient} presents to the sibling
 * {@code /bff/user/internal/notifications} endpoint — minted from the
 * {@code app.casdoor.systems.{base-url,client-id,client-secret}} credentials, cached +
 * re-minted by the token {@link Supplier} (see {@link FindingActivationReconcilerConfig}),
 * forwarded as {@code Authorization: Bearer <token>} on every call.
 *
 * <h3>GATED, fail-by-error (NOT fail-closed-suppress)</h3>
 * <ul>
 *   <li>The bean is ALWAYS injected non-null but real calls are gated by
 *       {@code character-moderation.reconciler.enabled} (default {@code false}); with the
 *       gate OFF {@link #applyModeration} returns {@link Outcome#FAILED} WITHOUT a call —
 *       so the reconciler does NOT advance its cursor past a row it never actually pushed
 *       (a part/sticker must never be silently left PENDING under the impression it was
 *       flipped). The in-cluster deployment flips the gate true once both contracts are
 *       reachable.</li>
 *   <li>On a real call: any 2xx (the sink flipped the PENDING row) OR a 404 (the sink
 *       idempotently no-op'd an already-flipped / unknown id — it surfaces that as a 404,
 *       not a 2xx) → {@link Outcome#APPLIED}; both mean the row is in its terminal state, so
 *       both are SUCCESS for the cursor's contiguous-advance. A transport error / other 4xx
 *       (400 bad-status, 401/403 auth) / 5xx / timeout → {@link Outcome#FAILED}: the
 *       reconciler advances the cursor NO FURTHER (this id + everything after is re-polled
 *       next tick).</li>
 * </ul>
 */
public class UserBffCharacterModerationClient {

    private static final Logger log = LoggerFactory.getLogger(UserBffCharacterModerationClient.class);

    /** Bound the call so a slow user-bff never stalls a reconcile tick. */
    private static final Duration CALL_TIMEOUT = Duration.ofSeconds(5);

    /** The user-bff sink path template (#87): {kind}=parts|stickers, {id}=subjectRef. */
    static final String PATH_TEMPLATE = "/bff/user/internal/character/{kind}/{id}/moderation";

    /** The sink {kind} path segment for the character-part surface. */
    static final String KIND_PARTS = "parts";
    /** The sink {kind} path segment for the character-sticker surface. */
    static final String KIND_STICKERS = "stickers";

    private final WebClient http;
    private final boolean enabled;
    private final Supplier<Mono<String>> serviceToken;

    /**
     * @param http         WebClient pre-pointed at user-bff's base URL.
     * @param enabled      whether to make real calls (false short-circuits to FAILED so the
     *                     cursor never advances over an un-pushed row).
     * @param serviceToken supplies a current Casdoor SERVICE bearer (cached / re-minted).
     */
    public UserBffCharacterModerationClient(WebClient http, boolean enabled,
                                            Supplier<Mono<String>> serviceToken) {
        this.http = http;
        this.enabled = enabled;
        this.serviceToken = serviceToken;
    }

    public boolean enabled() {
        return enabled;
    }

    /** The terminal verdict of a single moderation push. */
    public enum Outcome {
        /** The sink accepted the push (flipped PENDING, or idempotently no-op'd already-flipped).
         *  The cursor MAY advance past this id (subject to the contiguous-prefix invariant). */
        APPLIED,
        /** Gate off / transport error / non-2xx / timeout — push NOT confirmed. The cursor
         *  must NOT advance past this id; it is re-polled next tick. */
        FAILED
    }

    /**
     * POST one moderation outcome to user-bff. Never throws: maps every transport/status
     * failure to {@link Outcome#FAILED} so the reconciler decides advance-vs-halt (the
     * reconciler never hard-fails out of its tick).
     *
     * @param kind       {@link #KIND_PARTS} or {@link #KIND_STICKERS} (chosen by surface)
     * @param subjectRef the user-bff row id ({@code {id}} path segment)
     * @param status     {@code "ACTIVE"} or {@code "REJECTED"}
     * @param findingId  the federation finding id (audit + sink-side dedup)
     * @param reviewer   the resolving moderator (audit)
     */
    public Mono<Outcome> applyModeration(String kind, long subjectRef, String status,
                                         long findingId, String reviewer) {
        if (!enabled) {
            // Sink not wired in this environment: report FAILED (NOT a false success) so the
            // reconciler leaves the cursor where it is — the row stays eligible for a real
            // push once the gate is flipped on. (Unlike notifications, a moderation flip must
            // never be "skipped" past — a stranded PENDING row is the exact failure mode we
            // guard against.)
            log.debug("[char-mod-reconcile] user-bff sink gate OFF; FAILED (no call) kind={} id={}",
                    kind, subjectRef);
            return Mono.just(Outcome.FAILED);
        }
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("status", status);
        body.put("findingId", findingId);
        body.put("reviewer", reviewer);
        return serviceToken.get()
                .flatMap(token -> http.post()
                        .uri(PATH_TEMPLATE, kind, subjectRef)
                        .contentType(MediaType.APPLICATION_JSON)
                        // Reused VERBATIM from the platform ROLE_SERVICE pattern:
                        // Authorization: Bearer <Casdoor client_credentials JWT>.
                        .headers(h -> h.setBearerAuth(token))
                        .bodyValue(body)
                        .retrieve()
                        // IDEMPOTENT no-op = SUCCESS. The #87 sink flips ONLY a PENDING row and
                        // surfaces an already-flipped / unknown id as a 404 (its
                        // resolve{Part,Sticker} does switchIfEmpty→notFound). On a retry — after a
                        // crash/leadership-handoff between the flips and the single cursor write —
                        // the same rows are re-pushed; they are now ACTIVE/REJECTED, so the sink
                        // returns 404. Treat that 404 as APPLIED (the row IS in its terminal state)
                        // so the cursor advances instead of wedging forever at that id. Same
                        // idiom as AnnouncementMastodonClient (delete-already-deleted = 404 = OK).
                        .onStatus(s -> s.value() == 404, resp -> Mono.empty())
                        // Any 2xx (flipped) or the swallowed 404 (already-flipped) is a success.
                        .toBodilessEntity())
                .timeout(CALL_TIMEOUT)
                .map(ignored -> Outcome.APPLIED)
                .doOnNext(o -> log.info("[char-mod-reconcile] applied moderation kind={} id={} "
                        + "status={} findingId={}", kind, subjectRef, status, findingId))
                .onErrorResume(e -> {
                    // Transport / non-2xx / timeout: DO NOT advance — re-polled next tick.
                    log.warn("[char-mod-reconcile] user-bff moderation push FAILED kind={} id={} "
                            + "findingId={} (halt cursor, retry next tick): {}",
                            kind, subjectRef, findingId, e.toString());
                    return Mono.just(Outcome.FAILED);
                });
    }
}
