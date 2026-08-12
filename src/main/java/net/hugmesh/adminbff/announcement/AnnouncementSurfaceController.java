package net.hugmesh.adminbff.announcement;

import io.swagger.v3.oas.annotations.Operation;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;

import java.util.Map;

/**
 * Read-only announcement feeds the surface UIs consume. Each returns only the
 * announcements currently ACTIVE on that surface (published, in-window, with the
 * relevant target flag) — the active-window filtering lives in
 * {@link AnnouncementService}/{@link AnnouncementRepository}.
 *
 * <ul>
 *   <li>{@code GET /bff/announcements/home}        — AUTHENTICATED. The logged-in
 *       HOME top-banner feed (target_home).</li>
 *   <li>{@code GET /bff/announcements/forum}       — AUTHENTICATED. The forum
 *       main-page banner feed (target_forum) — the hugmesh-forum-ui that consumes
 *       it is built later with the separate phpBB forum-ui; this endpoint is exposed
 *       now.</li>
 *   <li>{@code GET /bff/public/announcements/login} — UNAUTHENTICATED. The public
 *       login-page feed (target_login), shown to anonymous visitors. Gated permitAll
 *       in BOTH SecurityConfig filter chains (and PUBLIC at the gateway).</li>
 * </ul>
 *
 * <p>{@code body_html} in these feeds was sanitised server-side at create/update;
 * the UIs still render it inside a sandboxed null-origin srcdoc iframe (never raw
 * innerHTML). {@code akkoma_ref}/{@code created_by} are internal and not surfaced
 * ({@code akkoma_ref} is {@code @JsonIgnore}d on the record).
 */
@RestController
public class AnnouncementSurfaceController {

    private final AnnouncementService service;

    public AnnouncementSurfaceController(AnnouncementService service) {
        this.service = service;
    }

    /** Authenticated home top-banner feed. */
    @Operation(summary = "Home", operationId = "announcementSurfaceHome")
    @GetMapping("/bff/announcements/home")
    public Mono<Map<String, Object>> home() {
        return service.activeForHome().collectList().map(list -> Map.of("announcements", list));
    }

    /** Authenticated forum main-page feed (forum-ui consumes it later). */
    @Operation(summary = "Forum", operationId = "announcementSurfaceForum")
    @GetMapping("/bff/announcements/forum")
    public Mono<Map<String, Object>> forum() {
        return service.activeForForum().collectList().map(list -> Map.of("announcements", list));
    }

    /** Public (unauthenticated) login-page feed for anonymous visitors. */
    @Operation(summary = "Login", operationId = "announcementSurfaceLogin")
    @GetMapping("/bff/public/announcements/login")
    public Mono<Map<String, Object>> login() {
        return service.activeForLogin().collectList().map(list -> Map.of("announcements", list));
    }
}
