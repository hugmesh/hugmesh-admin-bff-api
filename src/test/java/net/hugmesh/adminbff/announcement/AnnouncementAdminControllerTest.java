package net.hugmesh.adminbff.announcement;
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
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import net.hugmesh.adminbff.config.SecurityConfig;
import net.hugmesh.commons.security.PrincipalDomain;
import net.hugmesh.commons.web.ApiException;
import net.hugmesh.adminbff.web.ApiExceptionHandler;
import net.hugmesh.adminbff.web.ValidationExceptionHandler;
import net.hugmesh.adminbff.web.dto.AnnouncementRequest;

import java.time.Instant;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.mockJwt;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.springSecurity;

/**
 * Web-layer contract for the ADMIN announcements CRUD: ADMIN gating (@PreAuthorize
 * via SecurityConfig's @EnableReactiveMethodSecurity), jakarta bean-validation 400s
 * ({error,fields} via ValidationExceptionHandler), and the cross-field /
 * not-found application errors (400/404 via ApiExceptionHandler). The service is
 * mocked; the deeper sanitiser/akkoma behaviour is covered in AnnouncementServiceTest.
 */
@WebFluxTest(controllers = AnnouncementAdminController.class)
@Import({SecurityConfig.class, net.hugmesh.commons.security.DomainRegistry.class, ValidationExceptionHandler.class, ApiExceptionHandler.class})
class AnnouncementAdminControllerTest {

    @Autowired ApplicationContext context;

    WebTestClient web;

    @BeforeEach
    void setUpWebTestClient() {
        web = WebTestClient.bindToApplicationContext(context).apply(springSecurity()).build();
    }

    @MockitoBean AnnouncementService service;
    @MockitoBean ReactiveJwtDecoder jwtDecoder;
    @MockitoBean net.hugmesh.authcore.provision.GatewayRevocationClient revocations;

    private WebTestClient asAdmin() {
        return web.mutateWith(mockJwt().authorities(
                new SimpleGrantedAuthority("ROLE_USER"), new SimpleGrantedAuthority("ROLE_ADMIN")));
    }

    private WebTestClient asUser() {
        return web.mutateWith(mockJwt().authorities(new SimpleGrantedAuthority("ROLE_USER")));
    }

    private static Announcement row(String id, String state) {
        return new Announcement(id, "Title", "<p>body</p>", "html", state,
                true, false, false, false, 0, null, null, "UTC", true, "admin@x", null,
                Instant.now(), Instant.now(), "default");
    }

    private static final String VALID_BODY =
            "{\"title\":\"Heads up\",\"body_html\":\"<p>hi</p>\",\"target_home\":true}";

    // ── create ──────────────────────────────────────────────────────────
    @Test
    void create_valid_returns201AndRow() {
        when(service.create(any(AnnouncementRequest.class), anyString(), any(PrincipalDomain.class)))
                .thenReturn(Mono.just(row("new-1", "draft")));
        asAdmin().post().uri("/bff/admin/announcements").contentType(MediaType.APPLICATION_JSON)
                .bodyValue(VALID_BODY)
                .exchange().expectStatus().isCreated()
                .expectBody()
                .jsonPath("$.id").isEqualTo("new-1")
                .jsonPath("$.target_home").isEqualTo(true)
                // akkoma_ref and domain must never be serialised.
                .jsonPath("$.akkomaRef").doesNotExist()
                .jsonPath("$.akkoma_ref").doesNotExist()
                .jsonPath("$.domain").doesNotExist();
    }

    @Test
    void create_blankTitle_400_andNoServiceCall() {
        asAdmin().post().uri("/bff/admin/announcements").contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"title\":\"\",\"body_html\":\"<p>hi</p>\",\"target_home\":true}")
                .exchange().expectStatus().isBadRequest()
                .expectBody()
                .jsonPath("$.error").isEqualTo("validation failed")
                .jsonPath("$.fields.title").exists();
        verify(service, never()).create(any(), anyString(), any());
    }

    @Test
    void create_missingBody_400() {
        // The field-error key is the Java property name (bodyHtml), matching the
        // existing urlPattern convention in AdminControllerValidationTest.
        asAdmin().post().uri("/bff/admin/announcements").contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"title\":\"T\",\"target_home\":true}")
                .exchange().expectStatus().isBadRequest()
                .expectBody().jsonPath("$.fields.bodyHtml").exists();
    }

    @Test
    void create_badState_400() {
        asAdmin().post().uri("/bff/admin/announcements").contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"title\":\"T\",\"body_html\":\"<p>h</p>\",\"state\":\"on-fire\",\"target_home\":true}")
                .exchange().expectStatus().isBadRequest()
                .expectBody().jsonPath("$.fields.state").exists();
    }

    @Test
    void create_noTargetFlag_400_fromServiceCrossFieldRule() {
        when(service.create(any(AnnouncementRequest.class), anyString(), any(PrincipalDomain.class)))
                .thenReturn(Mono.error(ApiException.badRequest(
                        "at least one target surface (target_home/target_login/target_akkoma/target_forum) is required")));
        asAdmin().post().uri("/bff/admin/announcements").contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"title\":\"T\",\"body_html\":\"<p>h</p>\"}")
                .exchange().expectStatus().isBadRequest()
                .expectBody().jsonPath("$.error").value(org.hamcrest.Matchers.containsString("at least one target"));
    }

    // ── list / get ──────────────────────────────────────────────────────
    @Test
    void list_returnsAnnouncements() {
        when(service.list(any(PrincipalDomain.class))).thenReturn(Flux.just(row("a1", "published")));
        asAdmin().get().uri("/bff/admin/announcements").exchange().expectStatus().isOk()
                .expectBody().jsonPath("$.announcements[0].id").isEqualTo("a1");
    }

    @Test
    void get_unknown_404() {
        when(service.get(eq("missing"), any(PrincipalDomain.class))).thenReturn(Mono.error(
                new ApiException(org.springframework.http.HttpStatus.NOT_FOUND, "announcement 'missing' not found")));
        asAdmin().get().uri("/bff/admin/announcements/missing").exchange().expectStatus().isNotFound()
                .expectBody().jsonPath("$.error").value(org.hamcrest.Matchers.containsString("not found"));
    }

    // ── update / delete ─────────────────────────────────────────────────
    @Test
    void update_valid_returnsRow() {
        when(service.update(eq("a1"), any(AnnouncementRequest.class), anyString(), any(PrincipalDomain.class)))
                .thenReturn(Mono.just(row("a1", "published")));
        asAdmin().put().uri("/bff/admin/announcements/a1").contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"title\":\"T\",\"body_html\":\"<p>h</p>\",\"state\":\"published\",\"target_home\":true}")
                .exchange().expectStatus().isOk()
                .expectBody().jsonPath("$.state").isEqualTo("published");
    }

    @Test
    void delete_returns204() {
        when(service.delete(eq("a1"), any(PrincipalDomain.class))).thenReturn(Mono.empty());
        asAdmin().delete().uri("/bff/admin/announcements/a1").exchange().expectStatus().isNoContent();
    }

    // ── admin gating ────────────────────────────────────────────────────
    @Test
    void create_nonAdmin_403_andNoServiceCall() {
        asUser().post().uri("/bff/admin/announcements").contentType(MediaType.APPLICATION_JSON)
                .bodyValue(VALID_BODY)
                .exchange().expectStatus().isForbidden();
        verify(service, never()).create(any(), anyString(), any());
    }

    @Test
    void list_nonAdmin_403() {
        asUser().get().uri("/bff/admin/announcements").exchange().expectStatus().isForbidden();
    }

    @Test
    void list_unauthenticated_401() {
        web.get().uri("/bff/admin/announcements").exchange().expectStatus().isUnauthorized();
    }
}
