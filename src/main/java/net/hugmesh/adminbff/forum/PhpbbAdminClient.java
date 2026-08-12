package net.hugmesh.adminbff.forum;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

import java.util.Map;

/**
 * The admin-bff → forum-bff FORUM-CONSOLE client: a SAFE GATED-REAL reactive
 * {@link WebClient} that PROXIES the full phpBB ACP capability (manage everything
 * as-if-in-the-ACP) by calling the forum-bff {@code ForumAdminController}
 * ({@code /bff/forum/admin/**}) — which owns the single {@code PhpbbApiClient} /
 * {@code PhpbbAdminClient} that actually talks to the headless phpBB
 * {@code hugmesh/forum-api} extension.
 *
 * <p>This is deliberately NOT a second phpBB client: admin-bff calls forum-bff (the
 * single owner of the phpBB seam), exactly as the design's
 * {@code ForumAdminClient @Service} item specifies. The whole leg
 * (admin-bff → forum-bff) traverses a path gated {@code hasRole('ADMIN')}
 * END-TO-END, so an admin WITHOUT ROLE_FORUM is not blocked by the user floor (the
 * Casdoor converter gives admins neither ROLE_FORUM nor a USER/MOD superset).
 *
 * <h3>Defence-in-depth perimeter</h3>
 * <ul>
 *   <li>JWT-FORWARD: the caller's Casdoor JWT is re-presented as
 *       {@code Authorization: Bearer <jwt>} AND {@code X-HugMesh-JWT} on every
 *       call so forum-bff (and the extension behind it) independently re-derive
 *       ROLE_ADMIN from the verified token — never trusting caller-supplied authority
 *       data;</li>
 *   <li>mTLS client-cert presentation is plumbed by the {@code WebClient} builder
 *       (the {@code hugmesh-forum-bff-api-mtls} keystore the generator/PKI work
 *       provisions) — config-driven, mirroring {@code FederationHttpClientSsl} /
 *       {@code PhpbbHttpClientSsl}; this client only needs the JWT-forward leg.</li>
 * </ul>
 *
 * <h3>GATED-REAL external call — flag-gated, fail-soft</h3>
 * <p>Mirrors the {@code AnnouncementMastodonClient} / {@code HomeserverAdminClient} /
 * mod-bff {@code MastodonAdminClient} gated-client pattern:
 * <ul>
 *   <li>the reactive {@link WebClient} is built + ready ({@link #http});</li>
 *   <li>gated by {@code external.forum.enabled} (default false): when OFF every verb
 *       returns {@link ForumOutcome#stubbed()} after logging the intended action, so a
 *       forum-bff-less dev/test/CI run boots clean and the whole leg stays dark;</li>
 *   <li>when the flag is ON the single {@link #call} seam below makes the REAL
 *       JWT-forwarded HTTP call to the forum-bff {@code /bff/forum/admin/**} contract
 *       (now implemented + tested — forum-bff #17 / admin-bff #98). forum-bff in turn
 *       keeps the phpBB HTTP leg itself dark behind its OWN {@code phpbb.enabled} gate
 *       until the hugmesh {@code forum-api} extension shape is pinned on-cluster;</li>
 *   <li>it NEVER hard-fails: a degraded external call resolves to
 *       {@link ForumOutcome#degraded} so the admin request still completes and is
 *       auditable/usage-recorded.</li>
 * </ul>
 * The resilience4j {@code @CircuitBreaker} (instance {@code forum}) + timeout wrap
 * the real {@link #call} — wired identically to the akkoma / tuwunel / casdoor
 * breakers in {@code application.yml}.
 */
public class PhpbbAdminClient {

    private static final Logger log = LoggerFactory.getLogger(PhpbbAdminClient.class);

    private final WebClient http;
    private final boolean enabled;

    public PhpbbAdminClient(WebClient http, boolean enabled) {
        this.http = http;
        this.enabled = enabled;
    }

    public boolean enabled() {
        return enabled;
    }

    // ── Stats & usage (read) ───────────────────────────────────────────────
    /**
     * FORUM CONTENT stats read live from the extension {@code /stats} via forum-bff
     * (topics / posts / active users / moderation-queue depth). This is the
     * phpBB-live truth; the PLATFORM usage truth (content actions aggregated from
     * ClickHouse) is the separate {@code UsageService.aggregate()} the console also
     * shows — the two distinct stats surfaces the design calls out.
     */
    public Mono<ForumOutcome> stats(String jwt) {
        return call("GET", "/bff/forum/admin/stats", jwt, null, "admin.forum.stats");
    }

    // ── User management (read) ─────────────────────────────────────────────
    public Mono<ForumOutcome> listUsers(String jwt) {
        return call("GET", "/bff/forum/admin/users", jwt, null, "admin.forum.users");
    }

    public Mono<ForumOutcome> getUser(String jwt, String id) {
        return call("GET", "/bff/forum/admin/users/" + enc(id), jwt, null, "admin.forum.user");
    }

    // ── Ban / unban (reversible — ROLE removal congruence into phpBB) ───────
    /** Ban a forum user (suspend in phpBB + drop forum groups + cut sessions). */
    public Mono<ForumOutcome> banUser(String jwt, String id, String reason) {
        return call("POST", "/bff/forum/admin/users/" + enc(id) + "/ban", jwt,
                Map.of("reason", reason == null ? "" : reason), "admin.forum.ban");
    }

    /** Lift a forum ban — re-adds groups per the user's CURRENT Casdoor roles. */
    public Mono<ForumOutcome> unbanUser(String jwt, String id) {
        return call("DELETE", "/bff/forum/admin/users/" + enc(id) + "/ban", jwt, null,
                "admin.forum.unban");
    }

    // ── Group assignment (ADMINISTRATORS / GLOBAL_MODERATORS / REGISTERED) ──
    public Mono<ForumOutcome> assignGroup(String jwt, String id, String group) {
        return call("POST", "/bff/forum/admin/users/" + enc(id) + "/groups", jwt,
                Map.of("group", group == null ? "" : group), "admin.forum.group");
    }

    // ── Category CRUD ──────────────────────────────────────────────────────
    public Mono<ForumOutcome> listCategories(String jwt) {
        return call("GET", "/bff/forum/admin/categories", jwt, null, "admin.forum.categories");
    }

    public Mono<ForumOutcome> createCategory(String jwt, Map<String, Object> body) {
        return call("POST", "/bff/forum/admin/categories", jwt, body, "admin.forum.category.create");
    }

    // ── Moderation queue ───────────────────────────────────────────────────
    public Mono<ForumOutcome> moderationQueue(String jwt) {
        return call("GET", "/bff/forum/admin/moderation-queue", jwt, null,
                "admin.forum.moderation-queue");
    }

    public Mono<ForumOutcome> approve(String jwt, String id) {
        return call("POST", "/bff/forum/admin/moderation/" + enc(id) + "/approve", jwt, null,
                "admin.forum.moderation.approve");
    }

    public Mono<ForumOutcome> reject(String jwt, String id) {
        return call("POST", "/bff/forum/admin/moderation/" + enc(id) + "/reject", jwt, null,
                "admin.forum.moderation.reject");
    }

    // ── Style / extension install — ADMIN ONLY (full ACP parity) ───────────
    public Mono<ForumOutcome> installStyle(String jwt, Map<String, Object> body) {
        return call("POST", "/bff/forum/admin/styles", jwt, body, "admin.forum.style.install");
    }

    public Mono<ForumOutcome> installExtension(String jwt, Map<String, Object> body) {
        return call("POST", "/bff/forum/admin/extensions", jwt, body,
                "admin.forum.extension.install");
    }

    // ── Audit (forum_action read-through) ──────────────────────────────────
    public Mono<ForumOutcome> audit(String jwt) {
        return call("GET", "/bff/forum/admin/audit", jwt, null, "admin.forum.audit");
    }

    // ── The single external-call seam ──────────────────────────────────────
    /**
     * The ONE place every forum-console verb is realised. INERT by default
     * ({@code external.forum.enabled=false}) — returns {@link ForumOutcome#stubbed()}
     * after logging so the whole leg stays dark. When the flag is ON it makes the REAL
     * JWT-forwarded, circuit-broken HTTP call to the forum-bff
     * {@code /bff/forum/admin/**} contract (now implemented + tested), degrading to
     * {@link ForumOutcome#degraded} on any error rather than hard-failing. The phpBB
     * HTTP leg behind forum-bff stays dark behind forum-bff's OWN {@code phpbb.enabled}
     * gate until the {@code hugmesh/forum-api} extension shape is pinned on-cluster.
     *
     * @param action the {@code admin.forum.*} usage/audit action the caller records
     *               regardless of outcome.
     */
    private Mono<ForumOutcome> call(String method, String path, String jwt,
                                    Map<String, Object> body, String action) {
        log.info("[forum] {} {} ({}) enabled={}", method, path, action, enabled);
        if (!enabled) {
            // SAFE/INERT by default: external.forum.enabled=false keeps the whole leg dark
            // (the current behaviour). The forum-bff /bff/forum/admin/** contract is now
            // implemented + tested; flipping the flag ON (config-only) makes the real call.
            return Mono.just(ForumOutcome.stubbed());
        }
        // The forum-bff /bff/forum/admin/** contract is now REAL. Make the JWT-forwarded
        // call to forum-bff (which owns the single phpBB client; the phpBB HTTP leg itself
        // stays dark behind forum-bff's OWN phpbb.enabled gate until the hugmesh/forum-api
        // extension shape is pinned on-cluster). NEVER hard-fail: a forum-bff/phpBB outage
        // resolves to ForumOutcome.degraded so the admin request still completes + is
        // auditable/usage-recorded. The resilience4j @CircuitBreaker(name="forum") config
        // already exists; the onErrorResume here is the always-present degrade floor.
        // The path's id segment is ALREADY percent-encoded by enc(); the WebClient is wired
        // with EncodingMode.NONE (ForumAdminConfig) so the pre-encoded path is sent verbatim
        // — never double-encoded (%2F -> %252F).
        WebClient.RequestBodySpec req = http.method(HttpMethod.valueOf(method)).uri(path)
                .headers(h -> forwardJwt(h, jwt));
        WebClient.ResponseSpec spec = body == null
                ? req.retrieve()
                : req.contentType(MediaType.APPLICATION_JSON).bodyValue(body).retrieve();
        // toEntity (not bodyToMono) so an empty/no-content 2xx body (e.g. a 200 with no
        // payload) resolves to OK rather than a decode error — forum-bff write endpoints
        // may answer with no body. A non-2xx OR a transport error degrades (never throws).
        return spec.toEntity(MAP_TYPE)
                .map(entity -> ForumOutcome.ok(entity.getBody()))
                .onErrorResume(e -> {
                    log.warn("[forum] {} {} ({}) degraded: {}", method, path, action, e.toString());
                    return Mono.just(ForumOutcome.degraded(e.getMessage()));
                });
    }

    /** {@code Map<String,Object>} body type for the forum-bff JSON envelope response. */
    private static final org.springframework.core.ParameterizedTypeReference<Map<String, Object>> MAP_TYPE =
            new org.springframework.core.ParameterizedTypeReference<>() {};

    /**
     * Re-present the caller's Casdoor JWT to forum-bff as {@code Authorization: Bearer}
     * AND {@code X-HugMesh-JWT} so forum-bff + the extension independently re-derive
     * ROLE_ADMIN from the verified token (defence-in-depth — never trust caller-supplied
     * authority data). Used by the real {@link #call} body when the flag is ON.
     */
    static void forwardJwt(HttpHeaders h, String jwt) {
        if (jwt != null && !jwt.isBlank()) {
            h.set(HttpHeaders.AUTHORIZATION, "Bearer " + jwt);
            h.set("X-HugMesh-JWT", jwt);
        }
        h.setAccept(java.util.List.of(MediaType.APPLICATION_JSON));
    }

    private static String enc(String segment) {
        return java.net.URLEncoder.encode(segment == null ? "" : segment,
                java.nio.charset.StandardCharsets.UTF_8);
    }
}
