package systems.hugmesh.adminbff.forum;
import org.junit.jupiter.api.BeforeEach;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.boot.webflux.test.autoconfigure.WebFluxTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.reactive.server.WebTestClient;
import reactor.core.publisher.Mono;
import systems.hugmesh.adminbff.config.SecurityConfig;
import systems.hugmesh.adminbff.usage.UsageService;
import systems.hugmesh.adminbff.web.ApiExceptionHandler;
import systems.hugmesh.adminbff.web.ValidationExceptionHandler;

import java.util.Map;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.timeout;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.mockJwt;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.springSecurity;

/**
 * Web-layer contract for the ADMIN Forum Console seam ({@code /bff/admin/forum/**}):
 * ADMIN gating (@PreAuthorize via SecurityConfig's @EnableReactiveMethodSecurity),
 * the PhpbbAdminClient stub-seam proxying + console envelope, usage recording for
 * EVERY action regardless of outcome, and jakarta bean-validation 400s. The client
 * + UsageService are mocked; the deeper stub-seam behaviour is in PhpbbAdminClientTest.
 *
 * <p>KEY admin-console invariants asserted here:
 * <ul>
 *   <li>an admin WITHOUT ROLE_FORUM reaches every {@code /bff/admin/forum/**} endpoint
 *       (the leg is gated hasRole('ADMIN') end-to-end — the converter gives admins no
 *       ROLE_FORUM, so a forum-floor gate would wrongly block them);</li>
 *   <li>a ROLE_USER (and a ROLE_MOD-only / ROLE_FORUM-only non-admin) is 403 — the
 *       console is ADMIN-ONLY (style/extension install never reachable by mods);</li>
 *   <li>usage is recorded even when the forum-bff call is STUBBED (auditable seam).</li>
 * </ul>
 */
@WebFluxTest(controllers = ForumAdminController.class)
@Import({SecurityConfig.class, systems.hugmesh.commons.security.DomainRegistry.class, ValidationExceptionHandler.class, ApiExceptionHandler.class})
class ForumAdminControllerTest {

    @Autowired ApplicationContext context;

    WebTestClient web;

    @BeforeEach
    void setUpWebTestClient() {
        web = WebTestClient.bindToApplicationContext(context).apply(springSecurity()).build();
    }

    @MockitoBean PhpbbAdminClient forum;
    @MockitoBean UsageService usage;
    @MockitoBean ReactiveJwtDecoder jwtDecoder;
    @MockitoBean systems.hugmesh.authcore.provision.GatewayRevocationClient revocations;

    /** An ADMIN with NO ROLE_FORUM — the converter never grants admins ROLE_FORUM. */
    private WebTestClient asAdmin() {
        return web.mutateWith(mockJwt().authorities(
                new SimpleGrantedAuthority("ROLE_USER"), new SimpleGrantedAuthority("ROLE_ADMIN")));
    }

    private WebTestClient asUser() {
        return web.mutateWith(mockJwt().authorities(new SimpleGrantedAuthority("ROLE_USER")));
    }

    /** A mod who also holds the forum role — still NOT an admin → 403 on the console. */
    private WebTestClient asForumMod() {
        return web.mutateWith(mockJwt().authorities(
                new SimpleGrantedAuthority("ROLE_USER"),
                new SimpleGrantedAuthority("ROLE_MOD"),
                new SimpleGrantedAuthority("ROLE_FORUM")));
    }

    // ── stats / usage ───────────────────────────────────────────────────
    @Test
    void stats_admin_returnsEnvelope_andRecordsUsage() {
        when(forum.stats(any())).thenReturn(Mono.just(
                ForumOutcome.ok(Map.of("topics", 12, "posts", 88))));
        when(usage.record(anyString(), anyList(), anyString())).thenReturn(Mono.empty());

        asAdmin().get().uri("/bff/admin/forum/stats").exchange().expectStatus().isOk()
                .expectBody()
                .jsonPath("$.result").isEqualTo("ok")
                .jsonPath("$.topics").isEqualTo(12)
                .jsonPath("$.posts").isEqualTo(88);

        verify(usage, timeout(1000)).record(anyString(), anyList(), eq("admin.forum.stats"));
    }

    @Test
    void usage_admin_returnsAggregate_andRecordsUsage() {
        when(usage.aggregate()).thenReturn(Mono.just(Map.of("totalEvents", 5L)));
        when(usage.record(anyString(), anyList(), anyString())).thenReturn(Mono.empty());

        asAdmin().get().uri("/bff/admin/forum/usage").exchange().expectStatus().isOk()
                .expectBody().jsonPath("$.totalEvents").isEqualTo(5);

        verify(usage, timeout(1000)).record(anyString(), anyList(), eq("admin.forum.usage"));
    }

    // ── stubbed seam is still recorded ──────────────────────────────────
    @Test
    void users_stubbedSeam_stillReturnsEnvelope_andRecordsUsage() {
        when(forum.listUsers(any())).thenReturn(Mono.just(ForumOutcome.stubbed()));
        when(usage.record(anyString(), anyList(), anyString())).thenReturn(Mono.empty());

        asAdmin().get().uri("/bff/admin/forum/users").exchange().expectStatus().isOk()
                .expectBody().jsonPath("$.result").isEqualTo("stubbed");

        verify(usage, timeout(1000)).record(anyString(), anyList(), eq("admin.forum.users"));
    }

    // ── ban / unban (reversible) ────────────────────────────────────────
    @Test
    void ban_admin_proxiesAndRecords() {
        when(forum.banUser(any(), eq("u-1"), any())).thenReturn(Mono.just(ForumOutcome.ok()));
        when(usage.record(anyString(), anyList(), anyString())).thenReturn(Mono.empty());

        asAdmin().post().uri("/bff/admin/forum/users/u-1/ban").contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"reason\":\"spam\"}")
                .exchange().expectStatus().isOk()
                .expectBody().jsonPath("$.result").isEqualTo("ok");

        verify(forum).banUser(any(), eq("u-1"), eq("spam"));
        verify(usage, timeout(1000)).record(anyString(), anyList(), eq("admin.forum.ban"));
    }

    @Test
    void ban_admin_noBody_isAllowed() {
        when(forum.banUser(any(), eq("u-1"), any())).thenReturn(Mono.just(ForumOutcome.ok()));
        when(usage.record(anyString(), anyList(), anyString())).thenReturn(Mono.empty());

        asAdmin().post().uri("/bff/admin/forum/users/u-1/ban")
                .exchange().expectStatus().isOk();
        verify(forum).banUser(any(), eq("u-1"), eq(null));
    }

    @Test
    void unban_admin_proxiesAndRecords() {
        when(forum.unbanUser(any(), eq("u-1"))).thenReturn(Mono.just(ForumOutcome.ok()));
        when(usage.record(anyString(), anyList(), anyString())).thenReturn(Mono.empty());

        asAdmin().delete().uri("/bff/admin/forum/users/u-1/ban").exchange().expectStatus().isOk();
        verify(usage, timeout(1000)).record(anyString(), anyList(), eq("admin.forum.unban"));
    }

    // ── group assign — validation ───────────────────────────────────────
    @Test
    void assignGroup_validGroup_proxies() {
        when(forum.assignGroup(any(), eq("u-1"), eq("GLOBAL_MODERATORS")))
                .thenReturn(Mono.just(ForumOutcome.ok()));
        when(usage.record(anyString(), anyList(), anyString())).thenReturn(Mono.empty());

        asAdmin().post().uri("/bff/admin/forum/users/u-1/groups").contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"group\":\"GLOBAL_MODERATORS\"}")
                .exchange().expectStatus().isOk();
        verify(forum).assignGroup(any(), eq("u-1"), eq("GLOBAL_MODERATORS"));
    }

    @Test
    void assignGroup_badGroup_400_andNoProxy() {
        asAdmin().post().uri("/bff/admin/forum/users/u-1/groups").contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"group\":\"SUPERUSERS\"}")
                .exchange().expectStatus().isBadRequest()
                .expectBody().jsonPath("$.fields.group").exists();
        verify(forum, never()).assignGroup(any(), anyString(), anyString());
    }

    // ── category create — validation ────────────────────────────────────
    @Test
    void createCategory_valid_proxies() {
        when(forum.createCategory(any(), any())).thenReturn(Mono.just(ForumOutcome.ok()));
        when(usage.record(anyString(), anyList(), anyString())).thenReturn(Mono.empty());

        asAdmin().post().uri("/bff/admin/forum/categories").contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"name\":\"General\",\"description\":\"chat\"}")
                .exchange().expectStatus().isOk();
        verify(usage, timeout(1000)).record(anyString(), anyList(), eq("admin.forum.category.create"));
    }

    @Test
    void createCategory_blankName_400() {
        asAdmin().post().uri("/bff/admin/forum/categories").contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"name\":\"\"}")
                .exchange().expectStatus().isBadRequest()
                .expectBody().jsonPath("$.fields.name").exists();
    }

    // ── moderation queue ────────────────────────────────────────────────
    @Test
    void moderationQueue_admin_proxies() {
        when(forum.moderationQueue(any())).thenReturn(Mono.just(ForumOutcome.ok(Map.of("queue", java.util.List.of()))));
        when(usage.record(anyString(), anyList(), anyString())).thenReturn(Mono.empty());

        asAdmin().get().uri("/bff/admin/forum/moderation-queue").exchange().expectStatus().isOk()
                .expectBody().jsonPath("$.result").isEqualTo("ok");
    }

    // ── style / extension install — ADMIN ONLY ──────────────────────────
    @Test
    void installStyle_admin_proxiesAndRecords() {
        when(forum.installStyle(any(), any())).thenReturn(Mono.just(ForumOutcome.ok()));
        when(usage.record(anyString(), anyList(), anyString())).thenReturn(Mono.empty());

        asAdmin().post().uri("/bff/admin/forum/styles").contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"name\":\"prosilver\"}")
                .exchange().expectStatus().isOk();
        verify(usage, timeout(1000)).record(anyString(), anyList(), eq("admin.forum.style.install"));
    }

    @Test
    void installExtension_admin_proxiesAndRecords() {
        when(forum.installExtension(any(), any())).thenReturn(Mono.just(ForumOutcome.ok()));
        when(usage.record(anyString(), anyList(), anyString())).thenReturn(Mono.empty());

        asAdmin().post().uri("/bff/admin/forum/extensions").contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"name\":\"hugmesh/forum-api\"}")
                .exchange().expectStatus().isOk();
        verify(usage, timeout(1000)).record(anyString(), anyList(), eq("admin.forum.extension.install"));
    }

    @Test
    void installExtension_blankName_400() {
        asAdmin().post().uri("/bff/admin/forum/extensions").contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"name\":\"\"}")
                .exchange().expectStatus().isBadRequest();
    }

    // ── ADMIN gating (defence in depth) ─────────────────────────────────
    @Test
    void styleInstall_nonAdmin_403_andNoProxy() {
        asUser().post().uri("/bff/admin/forum/styles").contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"name\":\"prosilver\"}")
                .exchange().expectStatus().isForbidden();
        verify(forum, never()).installStyle(any(), any());
    }

    @Test
    void styleInstall_forumMod_403_neverReachableByMods() {
        // A mod (even one holding ROLE_FORUM) must NEVER reach style/extension install.
        asForumMod().post().uri("/bff/admin/forum/styles").contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"name\":\"prosilver\"}")
                .exchange().expectStatus().isForbidden();
        verify(forum, never()).installStyle(any(), any());
    }

    @Test
    void stats_nonAdmin_403() {
        asUser().get().uri("/bff/admin/forum/stats").exchange().expectStatus().isForbidden();
        verify(forum, never()).stats(any());
    }

    @Test
    void ban_forumMod_403() {
        asForumMod().post().uri("/bff/admin/forum/users/u-1/ban")
                .exchange().expectStatus().isForbidden();
        verify(forum, never()).banUser(any(), anyString(), any());
    }

    @Test
    void stats_unauthenticated_401() {
        web.get().uri("/bff/admin/forum/stats").exchange().expectStatus().isUnauthorized();
    }
}
