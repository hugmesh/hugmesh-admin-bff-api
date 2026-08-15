package net.hugmesh.adminbff.directory;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webflux.test.autoconfigure.WebFluxTest;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Import;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.reactive.server.WebTestClient;
import reactor.core.publisher.Mono;
import net.hugmesh.adminbff.config.SecurityConfig;
import net.hugmesh.adminbff.web.ApiExceptionHandler;
import net.hugmesh.adminbff.web.ValidationExceptionHandler;
import net.hugmesh.commons.security.DomainRegistry;
import net.hugmesh.commons.security.PrincipalDomain;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.mockJwt;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.springSecurity;

/**
 * HTTP authorization + scoping contract for {@link UserDirectoryController}
 * ({@code GET /bff/admin/users/search}). Driven through the REAL {@link SecurityConfig} so
 * the production {@code /bff/admin/** -> hasAnyRole('ADMIN','SUPERADMIN')} path gate is the
 * one under test, matching the {@code DomainCapabilityAdminControllerTest} idiom.
 *
 * <p>The scoping assertion here is deliberately about the ARGUMENT the controller passes
 * down: the {@link PrincipalDomain} must come from the validated token, and no request
 * parameter may influence it. A caller that appends {@code &domain=brandy} must be scoped
 * exactly as if they had not.
 */
@WebFluxTest(controllers = UserDirectoryController.class)
@Import({SecurityConfig.class, DomainRegistry.class, ValidationExceptionHandler.class,
        ApiExceptionHandler.class})
class UserDirectoryControllerTest {

    @Autowired ApplicationContext context;

    WebTestClient web;

    @BeforeEach
    void setUpWebTestClient() {
        web = WebTestClient.bindToApplicationContext(context).apply(springSecurity()).build();
    }

    @MockitoBean UserDirectoryService service;
    @MockitoBean ReactiveJwtDecoder jwtDecoder;

    /** The configured single issuer — {@link DomainRegistry} maps it to {@code "default"}.
     *  A JWT without it fails PrincipalDomain closed to {@code NO_DOMAIN}. */
    private static final String ISSUER = "https://id.hugmesh.net";

    private WebTestClient asAdmin() {
        return web.mutateWith(mockJwt().jwt(j -> j.issuer(ISSUER).claim("roles", List.of("admin")))
                .authorities(new SimpleGrantedAuthority("ROLE_USER"),
                        new SimpleGrantedAuthority("ROLE_ADMIN")));
    }

    private WebTestClient asSuperadmin() {
        return web.mutateWith(mockJwt().jwt(j -> j.issuer(ISSUER).claim("roles", List.of("superadmin")))
                .authorities(new SimpleGrantedAuthority("ROLE_USER"),
                        new SimpleGrantedAuthority("ROLE_SUPERADMIN")));
    }

    private WebTestClient asMod() {
        return web.mutateWith(mockJwt().jwt(j -> j.issuer(ISSUER))
                .authorities(new SimpleGrantedAuthority("ROLE_USER"),
                        new SimpleGrantedAuthority("ROLE_MOD")));
    }

    private WebTestClient asUser() {
        return web.mutateWith(mockJwt().jwt(j -> j.issuer(ISSUER))
                .authorities(new SimpleGrantedAuthority("ROLE_USER")));
    }

    // ════════════════════════ role gate ════════════════════════════════════════════

    @Test
    void anonymous_isUnauthorized() {
        web.get().uri("/bff/admin/users/search?q=al").exchange().expectStatus().isUnauthorized();
    }

    @Test
    void asUser_isForbidden() {
        asUser().get().uri("/bff/admin/users/search?q=al").exchange().expectStatus().isForbidden();
        verify(service, never()).search(any(), anyString(), anyInt());
    }

    @Test
    void asMod_isForbidden() {
        // A MOD never clears the coarse /bff/admin/** gate — the mod console cannot use
        // this endpoint, which is why mod-ui sources its own picker elsewhere.
        asMod().get().uri("/bff/admin/users/search?q=al").exchange().expectStatus().isForbidden();
        verify(service, never()).search(any(), anyString(), anyInt());
    }

    @Test
    void asAdmin_isAllowed() {
        when(service.search(any(), eq("al"), anyInt())).thenReturn(Mono.just(
                List.of(new DirectoryUser("alice", "alice@brandx.example", "google", "default"))));

        asAdmin().get().uri("/bff/admin/users/search?q=al")
                .exchange()
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$[0].username").isEqualTo("alice")
                .jsonPath("$[0].handle").isEqualTo("alice@brandx.example")
                .jsonPath("$[0].provider").isEqualTo("google")
                .jsonPath("$[0].domain").isEqualTo("default");
    }

    // ════════════════════════ scoping comes from the token ═════════════════════════

    @Test
    void scopeIsDerivedFromTheToken_notFromAnyRequestParameter() {
        when(service.search(any(), anyString(), anyInt())).thenReturn(Mono.just(List.of()));

        // A caller trying to name another brand gets their OWN scope regardless.
        asAdmin().get().uri("/bff/admin/users/search?q=al&domain=brandy")
                .exchange().expectStatus().isOk();

        var scope = org.mockito.ArgumentCaptor.forClass(PrincipalDomain.class);
        verify(service).search(scope.capture(), eq("al"), anyInt());
        assertThat(scope.getValue().domain()).isEqualTo(DomainRegistry.DEFAULT_DOMAIN);
        assertThat(scope.getValue().superadmin()).isFalse();
    }

    @Test
    void superadminScopeIsUnscoped() {
        when(service.search(any(), anyString(), anyInt())).thenReturn(Mono.just(List.of()));

        asSuperadmin().get().uri("/bff/admin/users/search?q=al").exchange().expectStatus().isOk();

        var scope = org.mockito.ArgumentCaptor.forClass(PrincipalDomain.class);
        verify(service).search(scope.capture(), eq("al"), anyInt());
        assertThat(scope.getValue().superadmin()).isTrue();
    }

    // ════════════════════════ parameter validation ═════════════════════════════════

    @Test
    void missingQuery_defaultsToBlank_andStillReturnsOk() {
        when(service.search(any(), eq(""), anyInt())).thenReturn(Mono.just(List.of()));

        asAdmin().get().uri("/bff/admin/users/search")
                .exchange().expectStatus().isOk()
                .expectBody().json("[]");
    }

    @Test
    void defaultLimitIsTheTypeaheadPageSize() {
        when(service.search(any(), anyString(), anyInt())).thenReturn(Mono.just(List.of()));

        asAdmin().get().uri("/bff/admin/users/search?q=al").exchange().expectStatus().isOk();

        verify(service).search(any(), eq("al"), eq(UserDirectoryController.DEFAULT_LIMIT));
    }

    @Test
    void limitAboveTheCeiling_isRejected() {
        asAdmin().get().uri("/bff/admin/users/search?q=al&limit=1000")
                .exchange().expectStatus().isBadRequest();
        verify(service, never()).search(any(), anyString(), anyInt());
    }

    @Test
    void limitBelowOne_isRejected() {
        asAdmin().get().uri("/bff/admin/users/search?q=al&limit=0")
                .exchange().expectStatus().isBadRequest();
        verify(service, never()).search(any(), anyString(), anyInt());
    }

    @Test
    void overlongQuery_isRejected() {
        asAdmin().get().uri("/bff/admin/users/search?q=" + "a".repeat(201))
                .exchange().expectStatus().isBadRequest();
        verify(service, never()).search(any(), anyString(), anyInt());
    }
}
