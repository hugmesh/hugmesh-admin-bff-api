package net.hugmesh.adminbff.appearance;

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
import net.hugmesh.adminbff.web.ApiExceptionHandler;
import net.hugmesh.adminbff.web.ValidationExceptionHandler;

import java.util.Map;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.mockJwt;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.springSecurity;

/**
 * Web-layer contract for the ADMIN-write-gated appearance-default endpoint: ADMIN
 * gating (@PreAuthorize via SecurityConfig's @EnableReactiveMethodSecurity), the
 * bean-validation 400 on an empty {@code prefs} body, and the resolved-view response.
 * The service is mocked; the deeper field/value validation is covered in
 * MastodonAppearanceDefaultServiceTest.
 */
@WebFluxTest(controllers = MastodonAppearanceDefaultAdminController.class)
@Import({SecurityConfig.class, net.hugmesh.commons.security.DomainRegistry.class,
        ValidationExceptionHandler.class, ApiExceptionHandler.class})
class MastodonAppearanceDefaultAdminControllerTest {

    @Autowired ApplicationContext context;

    WebTestClient web;

    @BeforeEach
    void setUpWebTestClient() {
        web = WebTestClient.bindToApplicationContext(context).apply(springSecurity()).build();
    }

    @MockitoBean MastodonAppearanceDefaultService service;
    @MockitoBean ReactiveJwtDecoder jwtDecoder;

    private WebTestClient asAdmin() {
        return web.mutateWith(mockJwt().authorities(
                new SimpleGrantedAuthority("ROLE_USER"), new SimpleGrantedAuthority("ROLE_ADMIN")));
    }

    private WebTestClient asUser() {
        return web.mutateWith(mockJwt().authorities(new SimpleGrantedAuthority("ROLE_USER")));
    }

    @Test
    void put_unauthenticated_401() {
        web.put().uri("/bff/admin/mastodon/appearance-default")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(Map.of("prefs", Map.of("theme", "mono")))
                .exchange().expectStatus().isUnauthorized();
        verify(service, never()).put(anyMap(), anyString(), anyString());
    }

    @Test
    void put_plainUser_403() {
        asUser().put().uri("/bff/admin/mastodon/appearance-default")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(Map.of("prefs", Map.of("theme", "mono")))
                .exchange().expectStatus().isForbidden();
        verify(service, never()).put(anyMap(), anyString(), anyString());
    }

    @Test
    void put_admin_valid_returnsResolvedView() {
        when(service.put(anyMap(), anyString(), anyString()))
                .thenReturn(Mono.just(Map.of("theme", "mono")));
        asAdmin().put().uri("/bff/admin/mastodon/appearance-default")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(Map.of("prefs", Map.of("theme", "mono")))
                .exchange().expectStatus().isOk()
                .expectBody().jsonPath("$.theme").isEqualTo("mono");
        verify(service).put(eq(Map.of("theme", "mono")), anyString(), anyString());
    }

    @Test
    void put_admin_emptyPrefs_isBadRequest_serviceNotReached() {
        asAdmin().put().uri("/bff/admin/mastodon/appearance-default")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(Map.of("prefs", Map.of()))
                .exchange().expectStatus().isBadRequest();
        verify(service, never()).put(anyMap(), anyString(), anyString());
    }
}
