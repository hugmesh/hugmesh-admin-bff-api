package net.hugmesh.adminbff.appearance;

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
import reactor.core.publisher.Mono;
import net.hugmesh.adminbff.config.SecurityConfig;

import java.util.Map;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.mockJwt;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.springSecurity;

/**
 * Web-layer contract for the READ-ONLY appearance-default surface:
 * {@code GET /bff/mastodon/appearance-default} requires an authenticated Casdoor JWT
 * (401 anonymous, 200 authenticated) — any authenticated caller (not just ADMIN) may
 * read their OWN brand's configured default.
 */
@WebFluxTest(controllers = MastodonAppearanceDefaultSurfaceController.class)
@Import({SecurityConfig.class, net.hugmesh.commons.security.DomainRegistry.class})
class MastodonAppearanceDefaultSurfaceControllerTest {

    @Autowired ApplicationContext context;

    WebTestClient web;

    @BeforeEach
    void setUpWebTestClient() {
        web = WebTestClient.bindToApplicationContext(context).apply(springSecurity()).build();
    }

    @MockitoBean MastodonAppearanceDefaultService service;
    @MockitoBean ReactiveJwtDecoder jwtDecoder;

    @Test
    void get_unauthenticated_401() {
        web.get().uri("/bff/mastodon/appearance-default").exchange().expectStatus().isUnauthorized();
    }

    @Test
    void get_authenticated_returnsResolvedDefault() {
        when(service.get(anyString())).thenReturn(Mono.just(Map.of("theme", "pastel-sky", "highContrast", true)));
        web.mutateWith(mockJwt().authorities(new SimpleGrantedAuthority("ROLE_USER")))
                .get().uri("/bff/mastodon/appearance-default")
                .exchange().expectStatus().isOk()
                .expectBody()
                .jsonPath("$.theme").isEqualTo("pastel-sky")
                .jsonPath("$.highContrast").isEqualTo(true);
    }

    @Test
    void get_noAdminDefaultConfigured_returnsEmptyObject() {
        when(service.get(anyString())).thenReturn(Mono.just(Map.of()));
        web.mutateWith(mockJwt().authorities(new SimpleGrantedAuthority("ROLE_USER")))
                .get().uri("/bff/mastodon/appearance-default")
                .exchange().expectStatus().isOk()
                .expectBody().json("{}");
    }

    @Test
    void get_usesCallerResolvedDomain() {
        when(service.get(anyString())).thenReturn(Mono.just(Map.of()));
        web.mutateWith(mockJwt().authorities(new SimpleGrantedAuthority("ROLE_USER")))
                .get().uri("/bff/mastodon/appearance-default")
                .exchange().expectStatus().isOk();
        verify(service).get(anyString());
    }
}
