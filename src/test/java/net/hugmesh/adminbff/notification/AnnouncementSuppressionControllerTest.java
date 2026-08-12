package net.hugmesh.adminbff.notification;
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
import net.hugmesh.adminbff.config.SecurityConfig;
import net.hugmesh.commons.security.DomainRegistry;
import net.hugmesh.adminbff.web.ValidationExceptionHandler;

import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.mockJwt;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.springSecurity;

/**
 * The per-domain {@code @system} broadcast suppression toggle: ADMIN gating (non-admin
 * → 403, and the repo is never touched), and the GET/PUT round-trip shape. Mirrors the
 * {@code AdminController} access-roles test wiring.
 */
@WebFluxTest(controllers = AnnouncementSuppressionController.class)
@Import({SecurityConfig.class, DomainRegistry.class, ValidationExceptionHandler.class})
class AnnouncementSuppressionControllerTest {

    @Autowired ApplicationContext context;

    WebTestClient web;

    @BeforeEach
    void setUpWebTestClient() {
        web = WebTestClient.bindToApplicationContext(context).apply(springSecurity()).build();
    }

    @MockitoBean AnnouncementSuppressionRepository repo;
    @MockitoBean ReactiveJwtDecoder jwtDecoder;

    private WebTestClient asAdmin() {
        return web.mutateWith(mockJwt().authorities(
                new SimpleGrantedAuthority("ROLE_USER"), new SimpleGrantedAuthority("ROLE_ADMIN")));
    }

    private WebTestClient asSuperadmin() {
        return web.mutateWith(mockJwt().authorities(
                new SimpleGrantedAuthority("ROLE_USER"),
                new SimpleGrantedAuthority("ROLE_ADMIN"),
                new SimpleGrantedAuthority("ROLE_SUPERADMIN")));
    }

    private WebTestClient asUser() {
        return web.mutateWith(mockJwt().authorities(new SimpleGrantedAuthority("ROLE_USER")));
    }

    @Test
    void get_asAdmin_returnsFlag() {
        when(repo.isSuppressed(anyString())).thenReturn(Mono.just(false));
        asAdmin().get().uri("/bff/admin/announcements/suppression")
                .exchange().expectStatus().isOk()
                .expectBody().jsonPath("$.suppressed").isEqualTo(false);
    }

    @Test
    void put_asAdmin_togglesFlag() {
        when(repo.setSuppressed(anyString(), anyBoolean(), anyString())).thenReturn(Mono.just(true));
        asAdmin().put().uri("/bff/admin/announcements/suppression")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"suppressed\":true}")
                .exchange().expectStatus().isOk()
                .expectBody().jsonPath("$.suppressed").isEqualTo(true);
        verify(repo).setSuppressed(anyString(), anyBoolean(), anyString());
    }

    @Test
    void put_asSuperadmin_isAllowed() {
        when(repo.setSuppressed(anyString(), anyBoolean(), anyString())).thenReturn(Mono.just(true));
        asSuperadmin().put().uri("/bff/admin/announcements/suppression")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"suppressed\":true}")
                .exchange().expectStatus().isOk();
    }

    @Test
    void get_asUser_isForbidden() {
        asUser().get().uri("/bff/admin/announcements/suppression")
                .exchange().expectStatus().isForbidden();
        verify(repo, never()).isSuppressed(anyString());
    }

    @Test
    void put_asUser_isForbidden_andNeverWrites() {
        asUser().put().uri("/bff/admin/announcements/suppression")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"suppressed\":true}")
                .exchange().expectStatus().isForbidden();
        verify(repo, never()).setSuppressed(anyString(), anyBoolean(), anyString());
    }

    @Test
    void put_missingBody_isBadRequest() {
        asAdmin().put().uri("/bff/admin/announcements/suppression")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{}")
                .exchange().expectStatus().isBadRequest();
        verify(repo, never()).setSuppressed(anyString(), anyBoolean(), anyString());
    }
}
