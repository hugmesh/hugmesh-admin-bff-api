package systems.hugmesh.adminbff.announcement;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

import java.util.Map;

/**
 * Reactive admin client that propagates a published announcement to akkoma (the
 * Mastodon-API fediverse server) as a LOCAL-ONLY server announcement — created via
 * the CONFIRMED pleroma-admin announcements API ({@code POST
 * /api/v1/pleroma/admin/announcements}, REQUIRED field {@code "content"}), which is
 * shown to instance users and is NOT federated out. On
 * unpublish/archive/expire/delete the post is removed via its id ({@code DELETE
 * /api/v1/pleroma/admin/announcements/{id}}).
 *
 * <p>(NOTE: the admin announcements live under {@code /api/v1/pleroma/admin/...} with
 * field {@code content}, NOT the non-admin {@code /api/v1/announcements} with
 * {@code text} that an earlier draft of this javadoc pointed at.)
 *
 * <h3>Live-stack probe results (2026-07, mainline Mastodon 4.3.1 standing in for Akkoma)</h3>
 * <p>Probed against the local compose stack's Mastodon (server-truth via the route
 * table + rails console in the container):
 * <ul>
 *   <li><b>Akkoma-ONLY (unconfirmable on this stack):</b> the create/remove verbs this
 *       client issues. Mainline Mastodon has NO {@code /api/v1/pleroma/*} routes at all
 *       — both {@code POST /api/v1/pleroma/admin/announcements} and {@code DELETE
 *       /api/v1/pleroma/admin/announcements/{id}} return route-level 404. Mainline also
 *       exposes NO REST admin-announcements API (its {@code /admin/announcements} is the
 *       HTML admin UI only), so the pleroma-admin request shape can only be confirmed
 *       against a real Akkoma.</li>
 *   <li><b>Mastodon-family CONFIRMED:</b> the announcement READ model this client's
 *       ref-handling relies on. A server-side-created announcement is served to users by
 *       {@code GET /api/v1/announcements} as {@code {"id":"<string>","content":"<rendered
 *       HTML>","all_day":false,...}} — i.e. the string {@code id} persisted here as
 *       {@code akkoma_ref} and the {@code content}/{@code all_day} field names match the
 *       Mastodon-family serializer (the underlying DB column is {@code text}; {@code
 *       content} is the API name). Announcements are instance-local notices, confirming
 *       the local-only intent.</li>
 *   <li><b>Honesty consequence (live-verified):</b> pointed at a server WITHOUT the
 *       pleroma-admin routes, CREATE 404s and resolves to {@link AkkomaOutcome#degraded}
 *       (never a fake created-ref) — pinned in the unit tests. REMOVE against such a
 *       server also 404s, which the idempotent-removal swallow maps to OK; that swallow
 *       is only meaningful against a real Akkoma (an already-deleted id), so the flag
 *       must not be flipped against a non-Akkoma target.</li>
 *   <li><b>Redirects are failures, not OK (live-verified):</b> Mastodon's force-HTTPS
 *       plain-HTTP port answers the DELETE with a method-preserving <b>308</b>
 *       (Content-Length: 0). WebClient's default status handlers only error on 4xx/5xx,
 *       so pre-fix a 3xx slipped through {@code retrieve()} as a false OK — and a false
 *       OK on remove makes {@code AnnouncementService} clear {@code akkoma_ref},
 *       permanently orphaning the real Akkoma announcement. Both seams now raise every
 *       non-2xx explicitly ({@code degraded:...}, remove keeping only the 404 swallow),
 *       pinned in the unit tests.</li>
 * </ul>
 *
 * <p>Wired against the in-cluster akkoma service (default
 * {@code http://akkoma.hugmesh-backend.svc.cluster.local:4000}, overridable via
 * {@code external.mastodon.base-url}), exactly mirroring the hugmesh-mod-bff-api
 * {@code MastodonAdminClient} + {@code ExternalAdminConfig} stub-seam pattern.
 *
 * <h3>Gated external call — honest, SAFE deferral</h3>
 * <p>The announcement create/remove legs are WIRED-REAL behind
 * {@code external.mastodon.enabled} (default false):
 * <ul>
 *   <li>the reactive {@link WebClient} is built + ready ({@link #http});</li>
 *   <li>DISABLED → no call: {@link #createLocalAnnouncement} / {@link #removeAnnouncement}
 *       return {@link AkkomaOutcome#stubbed()} after logging the intended action, so an
 *       akkoma-less dev/test/CI run boots clean and a no-flag cluster is a no-op;</li>
 *   <li>ENABLED → the REAL POST/DELETE is issued with the admin bearer (Vault
 *       {@code hugmesh/akkoma-admin} {@code token} via ESO, injected as
 *       {@code external.mastodon.admin-token}; placeholder-only, never inline). Create
 *       returns {@link AkkomaOutcome#created} carrying the new announcement id to persist
 *       as {@code akkoma_ref}; removal swallows a 404 as idempotent OK;</li>
 *   <li>it NEVER hard-fails: a degraded external call resolves to
 *       {@link AkkomaOutcome#degraded} so the publish still succeeds and the row is
 *       persisted/auditable.</li>
 * </ul>
 * The caller ({@code AnnouncementService}) always persists the announcement +
 * {@code akkoma_ref} (when a real ref is returned) regardless of this outcome.
 *
 * <p>The {@code @system} per-user notice leg ({@link #postLocalUserNotice}) stays a
 * SAFE GATED STUB (its per-user notice verb/token shape is still unconfirmed).
 */
public class AnnouncementMastodonClient {

    private static final Logger log = LoggerFactory.getLogger(AnnouncementMastodonClient.class);

    private final WebClient http;
    private final boolean enabled;
    /**
     * The akkoma privileged admin bearer (Vault {@code hugmesh/akkoma-admin}
     * property {@code token} via ESO), injected as {@code external.mastodon.admin-token}.
     * Placeholder-only — NEVER inline. Blank by default → no {@code Authorization}
     * header (lets the recording-ExchangeFunction tests exercise the real call shape).
     */
    private final String adminToken;

    public AnnouncementMastodonClient(WebClient http, boolean enabled) {
        this(http, enabled, null);
    }

    public AnnouncementMastodonClient(WebClient http, boolean enabled, String adminToken) {
        this.http = http;
        this.enabled = enabled;
        this.adminToken = adminToken;
    }

    public boolean enabled() {
        return enabled;
    }

    /**
     * Create a LOCAL-ONLY akkoma server announcement for a published, akkoma-targeted
     * announcement. On success the outcome carries the new akkoma announcement id
     * (to persist as {@code akkoma_ref} and use for later removal). STUBBED by
     * default — see class javadoc.
     */
    public Mono<AkkomaOutcome> createLocalAnnouncement(Announcement a) {
        log.info("[akkoma] create local-only announcement for '{}' (id={}, enabled={})",
                a.title(), a.id(), enabled);
        return doCreate(a);
    }

    /**
     * Remove a previously-created akkoma announcement by its {@code akkomaRef}
     * (unpublish/archive/expire/delete). Idempotent: a null/blank ref is a no-op OK.
     * STUBBED by default — see class javadoc.
     */
    public Mono<AkkomaOutcome> removeAnnouncement(String akkomaRef) {
        if (akkomaRef == null || akkomaRef.isBlank()) {
            return Mono.just(AkkomaOutcome.ok());
        }
        log.info("[akkoma] remove local announcement ref={} (enabled={})", akkomaRef, enabled);
        return doRemove(akkomaRef);
    }

    /**
     * Post a NEUTRAL {@code @system} LOCAL-ONLY notice to {@code localpart} — the akkoma
     * leg of the per-domain {@code @system} notifications sender (Notifications PR7).
     * Reuses this client's same local-only akkoma POST shape + gated stub-seam: STUBBED by
     * default (gated on {@code external.mastodon.enabled}); even when enabled it stays
     * STUBBED until the confirmed akkoma per-user notice verb/token is wired into
     * {@link #doPostLocalNotice}. NEVER hard-fails — a degraded call resolves to
     * {@link AkkomaOutcome#degraded}. The {@code body} is the neutral title+body the
     * {@code NotificationTemplate} composed (reason/ttl, NEVER the actor).
     */
    public Mono<AkkomaOutcome> postLocalUserNotice(String localpart, String body) {
        log.info("[akkoma] @system local notice to '{}' (enabled={})", localpart, enabled);
        return doPostLocalNotice(localpart, body);
    }

    /**
     * The {@code @system} per-user local-notice seam. STUBBED by default. The confirmed
     * call is roughly a direct-message / local notice as the {@code @system} account over
     * the akkoma-proxy mTLS sidecar (admin bearer), e.g.:
     * <pre>{@code
     *   return http.post().uri("/api/v1/statuses")
     *       .header("Authorization", "Bearer " + systemToken)
     *       .bodyValue(Map.of("status", "@" + localpart + " " + body, "visibility", "direct"))
     *       .retrieve().toBodilessEntity().thenReturn(AkkomaOutcome.ok())
     *       .onErrorResume(e -> Mono.just(AkkomaOutcome.degraded(e.getMessage())));
     * }</pre>
     */
    private Mono<AkkomaOutcome> doPostLocalNotice(String localpart, String body) {
        if (!enabled) {
            return Mono.just(AkkomaOutcome.stubbed());
        }
        log.warn("[akkoma] @system notice to '{}' is STUBBED — the akkoma per-user notice "
                + "verb/token are unconfirmed; wire the real call in doPostLocalNotice() before "
                + "relying on it (body length={})", localpart, body == null ? 0 : body.length());
        return Mono.just(AkkomaOutcome.stubbed());
    }

    /**
     * The single external-call seam for CREATE — WIRED-REAL behind {@link #enabled}.
     *
     * <p>Issues the CONFIRMED pleroma-admin call (admin bearer over the akkoma-proxy
     * mTLS sidecar):
     * <pre>{@code
     *   POST /api/v1/pleroma/admin/announcements
     *        {"content":"<title>\n\n<body_html>","all_day":false}   // REQUIRED field is "content"
     *   -> 200/201 with the created announcement JSON incl. "id"  (persist as akkoma_ref)
     * }</pre>
     * Local-only (NOT federated). NOT inherently idempotent (each POST creates a new
     * announcement) — the caller guards by only creating when {@code akkoma_ref} is
     * null/blank. DISABLED → no call (STUBBED). Failure → degraded (publish still
     * succeeds, row persisted).
     */
    private Mono<AkkomaOutcome> doCreate(Announcement a) {
        if (!enabled) {
            return Mono.just(AkkomaOutcome.stubbed());
        }
        String content = a.title() + "\n\n" + (a.bodyHtml() == null ? "" : a.bodyHtml());
        return http.post()
                .uri("/api/v1/pleroma/admin/announcements")
                .headers(this::applyAuth)
                .bodyValue(Map.of("content", content, "all_day", false))
                .retrieve()
                // Raise ANY non-2xx (incl. 3xx, which the default handlers pass through)
                // so a redirecting/misrouted target resolves DEGRADED — never an empty
                // Mono or a fabricated ref (same false-OK class as doRemove, see there).
                .onStatus(s -> !s.is2xxSuccessful(),
                        org.springframework.web.reactive.function.client.ClientResponse::createException)
                .bodyToMono(Map.class)
                .map(body -> AkkomaOutcome.created(body == null ? null : String.valueOf(body.get("id"))))
                .onErrorResume(e -> {
                    log.warn("[akkoma] create-announcement for '{}' degraded: {}", a.title(), e.toString());
                    return Mono.just(AkkomaOutcome.degraded(e.getMessage()));
                });
    }

    /**
     * The single external-call seam for REMOVE — WIRED-REAL behind {@link #enabled}.
     *
     * <p>Issues the CONFIRMED pleroma-admin delete:
     * <pre>{@code
     *   DELETE /api/v1/pleroma/admin/announcements/{id}   -> 200 {} on success
     * }</pre>
     * IDEMPOTENT for the BFF's purposes: a null/blank ref short-circuits to OK in
     * {@link #removeAnnouncement} before reaching here, and a 404 on an already-deleted
     * id is SWALLOWED to OK. Every OTHER non-2xx — including 3xx redirects, which the
     * default WebClient handlers would pass through as success — is raised and resolves
     * DEGRADED (never a false OK: the caller only clears {@code akkoma_ref} on OK, so a
     * false OK would orphan the live Akkoma post). DISABLED → no call (STUBBED).
     */
    private Mono<AkkomaOutcome> doRemove(String akkomaRef) {
        if (!enabled) {
            return Mono.just(AkkomaOutcome.stubbed());
        }
        return http.delete()
                .uri("/api/v1/pleroma/admin/announcements/{id}", akkomaRef)
                .headers(this::applyAuth)
                .retrieve()
                .onStatus(s -> s.value() == 404, resp -> Mono.empty()) // already-deleted = idempotent OK
                // Every OTHER non-2xx (incl. 3xx — the default handlers only error on
                // 4xx/5xx) is raised so it resolves DEGRADED, never a false OK. Live-
                // verified: the compose stack's Mastodon answers this DELETE on the
                // plain-HTTP port with a force-HTTPS 308 that retrieve() would otherwise
                // pass through — and a false OK here makes the caller clear akkoma_ref,
                // permanently orphaning the real Akkoma announcement.
                .onStatus(s -> !s.is2xxSuccessful(),
                        org.springframework.web.reactive.function.client.ClientResponse::createException)
                .toBodilessEntity()
                .thenReturn(AkkomaOutcome.ok())
                .onErrorResume(e -> {
                    log.warn("[akkoma] remove-announcement ref={} degraded: {}", akkomaRef, e.toString());
                    return Mono.just(AkkomaOutcome.degraded(e.getMessage()));
                });
    }

    /** Add the admin bearer iff a token is configured (placeholder-only; never inline). */
    private void applyAuth(org.springframework.http.HttpHeaders h) {
        if (adminToken != null && !adminToken.isBlank()) {
            h.setBearerAuth(adminToken);
        }
    }
}
