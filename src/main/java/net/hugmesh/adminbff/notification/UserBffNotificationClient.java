package net.hugmesh.adminbff.notification;

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
 * Reactive ROLE_SERVICE client over the user-bff INTERNAL in-app notification endpoint
 * (Notifications PR4 part A's contract):
 *
 * <pre>POST {user-bff}/bff/user/internal/notifications
 *   body { domain, userSubject, category, title, body, sourceTable, sourceId } -&gt; 200 {delivered:bool, ...}</pre>
 *
 * <h3>Auth (reused VERBATIM from the platform pattern part A gates on)</h3>
 * The endpoint is internal / ROLE_SERVICE-gated on the user-bff side via the canonical
 * {@code CasdoorAuthorities} converter ({@code roles} claim entry {@code service} ->
 * {@code ROLE_SERVICE}) and Spring {@code hasRole("SERVICE")} — the SAME mechanism
 * hugmesh-federation-api uses for {@code /api/federation/username/**}
 * ({@code hasAnyRole("SERVICE","ADMIN","SUPERADMIN")}). This client therefore presents a
 * Casdoor SERVICE-account JWT minted via the OAuth2 {@code client_credentials} grant
 * against hugmesh.systems Casdoor (no human login produces {@code ROLE_SERVICE}),
 * forwarded as {@code Authorization: Bearer <token>} on every call — exactly as
 * hugmesh-actions' {@code FederationUsernameClient.setBearerAuth} does. The token
 * {@link Supplier} caches + re-mints (see {@link UserBffNotificationConfig}); this
 * client just asks for "a current bearer" per call.
 *
 * <h3>GATED, fail-by-error (NOT fail-closed-suppress)</h3>
 * <ul>
 *   <li>The WebClient is always built + injected non-null, but {@link #enabled()} gates
 *       a real call: with the gate OFF (the default for a user-bff-less dev/test/CI run)
 *       {@link #deliverInApp} returns {@link Outcome#SUPPRESSED} WITHOUT a network call,
 *       so the reconciler records a {@code skipped} delivery and never blocks the cursor
 *       on an endpoint that isn't wired yet.</li>
 *   <li>On a real call: a 2xx with {@code delivered:true} -> {@link Outcome#DELIVERED};
 *       a 2xx with {@code delivered:false} (the recipient silenced this category) ->
 *       {@link Outcome#SUPPRESSED} (still terminal — the reconciler records {@code
 *       skipped} and will not retry). A transport error / 5xx / timeout -> {@link
 *       Outcome#FAILED}: the reconciler records NOTHING and the row is retried next tick
 *       (the call is NOT swallowed into a false success — unlike the username gate's
 *       fail-closed posture, an in-app notification must not be silently dropped).</li>
 * </ul>
 */
public class UserBffNotificationClient {

    private static final Logger log = LoggerFactory.getLogger(UserBffNotificationClient.class);

    /** Bound the call so a slow user-bff never stalls a reconcile tick. */
    private static final Duration CALL_TIMEOUT = Duration.ofSeconds(5);

    /** The contract path (part A). */
    static final String PATH = "/bff/user/internal/notifications";

    private final WebClient http;
    private final boolean enabled;
    private final Supplier<Mono<String>> serviceToken;

    /**
     * @param http         WebClient pre-pointed at user-bff's base URL.
     * @param enabled      whether to make real calls (false short-circuits to SUPPRESSED).
     * @param serviceToken supplies a current Casdoor SERVICE bearer (cached / re-minted).
     */
    public UserBffNotificationClient(WebClient http, boolean enabled,
                                     Supplier<Mono<String>> serviceToken) {
        this.http = http;
        this.enabled = enabled;
        this.serviceToken = serviceToken;
    }

    public boolean enabled() {
        return enabled;
    }

    /** The terminal verdict of an in-app delivery attempt. */
    public enum Outcome {
        /** user-bff accepted + delivered the in-app notification (record {@code sent}). */
        DELIVERED,
        /** user-bff accepted but suppressed it (recipient silenced) OR the gate is off —
         *  terminal, record {@code skipped}, never retry. */
        SUPPRESSED,
        /** transport error / 5xx / timeout — record NOTHING, retry next tick. */
        FAILED
    }

    /**
     * POST one in-app notification to user-bff (the part-A contract). Never throws: maps
     * every transport/status failure to {@link Outcome#FAILED} so the reconciler's per-row
     * handling decides retry-vs-record (the reconciler never hard-fails out of its tick).
     */
    @SuppressWarnings("unchecked")
    public Mono<Outcome> deliverInApp(UserBffNotification n) {
        if (!enabled) {
            // user-bff endpoint not wired in this environment: treat as terminally
            // suppressed so the cursor advances (no perpetual retry against a dead path).
            log.debug("[notify-reconcile] user-bff notify gate OFF; SUPPRESSED (no call) for outbox source={} :{}",
                    n.sourceTable(), n.sourceId());
            return Mono.just(Outcome.SUPPRESSED);
        }
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("domain", n.domain());
        body.put("userSubject", n.userSubject());
        body.put("category", n.category());
        body.put("title", n.title());
        body.put("body", n.body());
        body.put("sourceTable", n.sourceTable());
        body.put("sourceId", n.sourceId());
        return serviceToken.get()
                .flatMap(token -> http.post()
                        .uri(PATH)
                        .contentType(MediaType.APPLICATION_JSON)
                        // Reused VERBATIM from the platform ROLE_SERVICE pattern:
                        // Authorization: Bearer <Casdoor client_credentials JWT>.
                        .headers(h -> h.setBearerAuth(token))
                        .bodyValue(body)
                        .retrieve()
                        .bodyToMono(Map.class))
                .map(resp -> Boolean.FALSE.equals(((Map<String, Object>) resp).get("delivered"))
                        ? Outcome.SUPPRESSED
                        : Outcome.DELIVERED)
                // An empty 200 body still counts as delivered (the call succeeded).
                .defaultIfEmpty(Outcome.DELIVERED)
                .timeout(CALL_TIMEOUT)
                .onErrorResume(e -> {
                    // Transport / 5xx / timeout: DO NOT record a delivery — the row is
                    // retried next tick. Never propagate (the tick must not hard-fail).
                    log.warn("[notify-reconcile] user-bff notify failed for outbox source={} :{} "
                            + "(record nothing, retry next tick): {}",
                            n.sourceTable(), n.sourceId(), e.toString());
                    return Mono.just(Outcome.FAILED);
                });
    }
}
