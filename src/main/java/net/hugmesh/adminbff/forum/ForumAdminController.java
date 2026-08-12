package net.hugmesh.adminbff.forum;

import io.swagger.v3.oas.annotations.Operation;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;
import net.hugmesh.adminbff.usage.UsageService;
import net.hugmesh.adminbff.web.dto.ForumBanRequest;
import net.hugmesh.adminbff.web.dto.ForumCategoryRequest;
import net.hugmesh.adminbff.web.dto.ForumGroupRequest;
import net.hugmesh.adminbff.web.dto.ForumInstallRequest;
import net.hugmesh.commons.security.RoleName;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * ADMIN-only FORUM CONSOLE — the admin-bff seam that PROXIES the full phpBB ACP
 * capability (manage everything as-if-in-the-ACP) plus forum stats/usage, by calling
 * forum-bff's {@code ForumAdminController} ({@code /bff/forum/admin/**}) via the SAFE
 * GATED {@link PhpbbAdminClient} stub-seam. The raw phpBB ACP ({@code /adm/index.php})
 * is network-blocked; everything (users, groups, categories, moderation queue, styles,
 * extensions, stats) is manageable remotely through THESE APIs.
 *
 * <p>Admin gating is DEFENCE IN DEPTH, identical to {@code AnnouncementAdminController}
 * and the design's §8/§6 triple-defence:
 * <ul>
 *   <li>the gateway denies {@code /bff/admin/**} to non-admins (Postgres route-access
 *       row {@code /bff/admin/forum/** = ROLE_ADMIN});</li>
 *   <li>the resource-server filter re-applies {@code hasRole('ADMIN')} on the path
 *       ({@code SecurityConfig.commonRoutes} {@code /bff/admin/** -> hasRole("ADMIN")});</li>
 *   <li>{@code @PreAuthorize("hasRole('ADMIN')")} re-checks at every method here;</li>
 *   <li>and forum-bff + the phpBB extension independently re-derive ROLE_ADMIN from the
 *       forwarded JWT — never trusting caller-supplied authority.</li>
 * </ul>
 * The whole leg (admin-bff → forum-bff) is gated {@code hasRole('ADMIN')} END-TO-END,
 * so an admin WITHOUT ROLE_FORUM is not blocked by the forum user floor (the Casdoor
 * converter gives admins neither ROLE_FORUM nor a USER/MOD superset). Style/extension
 * install is ADMIN-ONLY here and lives ONLY under {@code /bff/admin/forum/**} (never
 * co-located with any mod-visible surface).
 *
 * <p>Every action is USAGE-RECORDED (module {@code admin-ui}) regardless of the
 * external outcome — the same {@code UsageService.record(...)} fire-and-forget pattern
 * the rest of {@code AdminController} uses — so STUBBED/degraded forum-bff calls are
 * still auditable. The response is the {@link ForumOutcome#asResponse()} envelope (the
 * returned payload merged with a {@code result} marker the console renders).
 *
 * <h3>Two distinct stats truths</h3>
 * <ul>
 *   <li>{@code GET /stats} — FORUM CONTENT counts (topics/posts/active users/queue
 *       depth) read LIVE from the phpBB extension via forum-bff (STUBBED until wired);</li>
 *   <li>{@code GET /usage} — PLATFORM usage aggregated from ClickHouse (the
 *       {@code UsageService} {@code forum.*}/{@code admin.forum.*} events), with the
 *       in-memory fallback — the same surface the admin Usage view uses.</li>
 * </ul>
 */
@RestController
@RequestMapping("/bff/admin/forum")
@Validated
public class ForumAdminController {

    private final PhpbbAdminClient forum;
    private final UsageService usage;

    public ForumAdminController(PhpbbAdminClient forum, UsageService usage) {
        this.forum = forum;
        this.usage = usage;
    }

    // ── Stats & usage ──────────────────────────────────────────────────────
    /** FORUM CONTENT stats (topics/posts/active users/queue depth) — live from phpBB. */
    @PreAuthorize("hasRole('ADMIN')")
    @Operation(summary = "Stats", operationId = "forumAdminStats")
    @GetMapping("/stats")
    public Mono<Map<String, Object>> stats(Authentication auth) {
        return forum.stats(jwt(auth)).map(envelope("admin.forum.stats", auth));
    }

    /** PLATFORM usage (ClickHouse forum / admin.forum aggregate, in-memory fallback). */
    @PreAuthorize("hasRole('ADMIN')")
    @Operation(summary = "Usage", operationId = "forumAdminUsage")
    @GetMapping("/usage")
    public Mono<Map<String, Object>> usage(Authentication auth) {
        return usage.aggregate()
                .doOnSuccess(v -> record("admin.forum.usage", auth));
    }

    // ── User management ────────────────────────────────────────────────────
    @PreAuthorize("hasRole('ADMIN')")
    @Operation(summary = "Users", operationId = "forumAdminUsers")
    @GetMapping("/users")
    public Mono<Map<String, Object>> users(Authentication auth) {
        return forum.listUsers(jwt(auth)).map(envelope("admin.forum.users", auth));
    }

    @PreAuthorize("hasRole('ADMIN')")
    @Operation(summary = "User", operationId = "forumAdminUser")
    @GetMapping("/users/{id}")
    public Mono<Map<String, Object>> user(@PathVariable @NotBlank @Size(max = 200) String id,
                                          Authentication auth) {
        return forum.getUser(jwt(auth), id).map(envelope("admin.forum.user", auth));
    }

    // ── Ban / unban (reversible) ───────────────────────────────────────────
    /** Ban a forum user — phpBB suspend + drop forum groups + cut sessions (REVERSIBLE). */
    @PreAuthorize("hasRole('ADMIN')")
    @Operation(summary = "Ban", operationId = "forumAdminBan")
    @PostMapping("/users/{id}/ban")
    public Mono<Map<String, Object>> ban(@PathVariable @NotBlank @Size(max = 200) String id,
                                         @Valid @RequestBody(required = false) ForumBanRequest body,
                                         Authentication auth) {
        String reason = body == null ? null : body.reason();
        return forum.banUser(jwt(auth), id, reason).map(envelope("admin.forum.ban", auth));
    }

    /** Lift a forum ban — re-adds groups per the user's CURRENT Casdoor roles. */
    @PreAuthorize("hasRole('ADMIN')")
    @Operation(summary = "Unban", operationId = "forumAdminUnban")
    @DeleteMapping("/users/{id}/ban")
    public Mono<Map<String, Object>> unban(@PathVariable @NotBlank @Size(max = 200) String id,
                                           Authentication auth) {
        return forum.unbanUser(jwt(auth), id).map(envelope("admin.forum.unban", auth));
    }

    // ── Group assignment ───────────────────────────────────────────────────
    @PreAuthorize("hasRole('ADMIN')")
    @Operation(summary = "Assign group", operationId = "forumAdminAssignGroup")
    @PostMapping("/users/{id}/groups")
    public Mono<Map<String, Object>> assignGroup(
            @PathVariable @NotBlank @Size(max = 200) String id,
            @Valid @RequestBody ForumGroupRequest body,
            Authentication auth) {
        return forum.assignGroup(jwt(auth), id, body.group())
                .map(envelope("admin.forum.group", auth));
    }

    // ── Category CRUD ──────────────────────────────────────────────────────
    @PreAuthorize("hasRole('ADMIN')")
    @Operation(summary = "Categories", operationId = "forumAdminCategories")
    @GetMapping("/categories")
    public Mono<Map<String, Object>> categories(Authentication auth) {
        return forum.listCategories(jwt(auth)).map(envelope("admin.forum.categories", auth));
    }

    @PreAuthorize("hasRole('ADMIN')")
    @Operation(summary = "Create category", operationId = "forumAdminCreateCategory")
    @PostMapping("/categories")
    public Mono<Map<String, Object>> createCategory(@Valid @RequestBody ForumCategoryRequest body,
                                                    Authentication auth) {
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("name", body.name());
        if (body.description() != null) payload.put("description", body.description());
        if (body.parentId() != null) payload.put("parentId", body.parentId());
        return forum.createCategory(jwt(auth), payload)
                .map(envelope("admin.forum.category.create", auth));
    }

    // ── Moderation queue ───────────────────────────────────────────────────
    @PreAuthorize("hasRole('ADMIN')")
    @Operation(summary = "Moderation queue", operationId = "forumAdminModerationQueue")
    @GetMapping("/moderation-queue")
    public Mono<Map<String, Object>> moderationQueue(Authentication auth) {
        return forum.moderationQueue(jwt(auth)).map(envelope("admin.forum.moderation-queue", auth));
    }

    @PreAuthorize("hasRole('ADMIN')")
    @Operation(summary = "Approve", operationId = "forumAdminApprove")
    @PostMapping("/moderation/{id}/approve")
    public Mono<Map<String, Object>> approve(@PathVariable @NotBlank @Size(max = 200) String id,
                                             Authentication auth) {
        return forum.approve(jwt(auth), id).map(envelope("admin.forum.moderation.approve", auth));
    }

    @PreAuthorize("hasRole('ADMIN')")
    @Operation(summary = "Reject", operationId = "forumAdminReject")
    @PostMapping("/moderation/{id}/reject")
    public Mono<Map<String, Object>> reject(@PathVariable @NotBlank @Size(max = 200) String id,
                                            Authentication auth) {
        return forum.reject(jwt(auth), id).map(envelope("admin.forum.moderation.reject", auth));
    }

    // ── Style / extension install — ADMIN ONLY ─────────────────────────────
    @PreAuthorize("hasRole('ADMIN')")
    @Operation(summary = "Install style", operationId = "forumAdminInstallStyle")
    @PostMapping("/styles")
    public Mono<Map<String, Object>> installStyle(@Valid @RequestBody ForumInstallRequest body,
                                                  Authentication auth) {
        return forum.installStyle(jwt(auth), Map.of("name", body.name()))
                .map(envelope("admin.forum.style.install", auth));
    }

    @PreAuthorize("hasRole('ADMIN')")
    @Operation(summary = "Install extension", operationId = "forumAdminInstallExtension")
    @PostMapping("/extensions")
    public Mono<Map<String, Object>> installExtension(@Valid @RequestBody ForumInstallRequest body,
                                                      Authentication auth) {
        return forum.installExtension(jwt(auth), Map.of("name", body.name()))
                .map(envelope("admin.forum.extension.install", auth));
    }

    // ── Audit ──────────────────────────────────────────────────────────────
    @PreAuthorize("hasRole('ADMIN')")
    @Operation(summary = "Audit", operationId = "forumAdminAudit")
    @GetMapping("/audit")
    public Mono<Map<String, Object>> audit(Authentication auth) {
        return forum.audit(jwt(auth)).map(envelope("admin.forum.audit", auth));
    }

    // ── helpers ────────────────────────────────────────────────────────────
    /**
     * Map a {@link ForumOutcome} to the console envelope AND fire-and-forget the usage
     * record for {@code action} — recorded REGARDLESS of outcome (STUBBED/degraded
     * stays auditable), exactly like {@code AdminController}'s usage calls.
     */
    private java.util.function.Function<ForumOutcome, Map<String, Object>> envelope(
            String action, Authentication auth) {
        return outcome -> {
            record(action, auth);
            return outcome.asResponse();
        };
    }

    private void record(String action, Authentication auth) {
        usage.record(actor(auth), List.of(RoleName.ADMIN.value()), action).subscribe();
    }

    /** The acting admin's identity (JWT subject/name) for the usage record. */
    private static String actor(Authentication auth) {
        return auth == null ? "admin" : auth.getName();
    }

    /**
     * The raw Casdoor JWT to forward to forum-bff (re-presented as Bearer +
     * {@code X-HugMesh-JWT} so forum-bff + the phpBB extension re-derive ROLE_ADMIN
     * from the verified token). Null when the caller is not a JWT principal (e.g. a
     * mock-authority test) — the stub-seam then simply forwards no token.
     */
    private static String jwt(Authentication auth) {
        if (auth instanceof JwtAuthenticationToken token) {
            return token.getToken().getTokenValue();
        }
        if (auth != null && auth.getCredentials() instanceof Jwt j) {
            return j.getTokenValue();
        }
        return null;
    }
}
