package systems.hugmesh.adminbff.announcement;
import org.junit.jupiter.api.BeforeEach;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.boot.webflux.test.autoconfigure.WebFluxTest;
import org.springframework.context.annotation.Import;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.reactive.server.WebTestClient;
import reactor.core.publisher.Flux;
import systems.hugmesh.adminbff.config.SecurityConfig;

import java.time.Instant;

import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.mockJwt;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.springSecurity;

/**
 * Web-layer contract for the surface announcement feeds:
 * <ul>
 *   <li>{@code GET /bff/public/announcements/login} is reachable WITHOUT a token
 *       (permitAll in both SecurityConfig chains);</li>
 *   <li>{@code GET /bff/announcements/home} + {@code /forum} require an
 *       authenticated Casdoor JWT (401 anonymous, 200 authenticated).</li>
 * </ul>
 */
@WebFluxTest(controllers = AnnouncementSurfaceController.class)
@Import({SecurityConfig.class, systems.hugmesh.commons.security.DomainRegistry.class})
class AnnouncementSurfaceControllerTest {

    @Autowired ApplicationContext context;

    WebTestClient web;

    @BeforeEach
    void setUpWebTestClient() {
        web = WebTestClient.bindToApplicationContext(context).apply(springSecurity()).build();
    }

    @MockitoBean AnnouncementService service;
    @MockitoBean ReactiveJwtDecoder jwtDecoder;

    private static Announcement row(String id) {
        return new Announcement(id, "Title", "<p>body</p>", "html", "published",
                true, true, false, true, 0, null, null, "UTC", true, "admin@x", null,
                Instant.now(), Instant.now(), "default");
    }

    // ── public login feed — NO token required ───────────────────────────
    @Test
    void login_reachableWithoutToken() {
        when(service.activeForLogin()).thenReturn(Flux.just(row("l1")));
        web.get().uri("/bff/public/announcements/login")
                .exchange().expectStatus().isOk()
                .expectBody().jsonPath("$.announcements[0].id").isEqualTo("l1");
    }

    @Test
    void login_doesNotLeakAkkomaRef() {
        when(service.activeForLogin()).thenReturn(Flux.just(row("l2")));
        web.get().uri("/bff/public/announcements/login")
                .exchange().expectStatus().isOk()
                .expectBody()
                .jsonPath("$.announcements[0].akkomaRef").doesNotExist()
                .jsonPath("$.announcements[0].akkoma_ref").doesNotExist()
                .jsonPath("$.announcements[0].domain").doesNotExist();
    }

    // ── home feed — authenticated ───────────────────────────────────────
    @Test
    void home_unauthenticated_401() {
        web.get().uri("/bff/announcements/home").exchange().expectStatus().isUnauthorized();
    }

    @Test
    void home_authenticated_200() {
        when(service.activeForHome()).thenReturn(Flux.just(row("h1")));
        web.mutateWith(mockJwt().authorities(new SimpleGrantedAuthority("ROLE_USER")))
                .get().uri("/bff/announcements/home").exchange().expectStatus().isOk()
                .expectBody().jsonPath("$.announcements[0].id").isEqualTo("h1");
    }

    // ── forum feed — authenticated ──────────────────────────────────────
    @Test
    void forum_unauthenticated_401() {
        web.get().uri("/bff/announcements/forum").exchange().expectStatus().isUnauthorized();
    }

    @Test
    void forum_authenticated_200() {
        when(service.activeForForum()).thenReturn(Flux.just(row("f1")));
        web.mutateWith(mockJwt().authorities(new SimpleGrantedAuthority("ROLE_USER")))
                .get().uri("/bff/announcements/forum").exchange().expectStatus().isOk()
                .expectBody().jsonPath("$.announcements[0].id").isEqualTo("f1");
    }
}
