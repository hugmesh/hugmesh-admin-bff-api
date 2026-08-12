package net.hugmesh.adminbff.desktop;
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
import reactor.core.publisher.Mono;
import net.hugmesh.adminbff.config.SecurityConfig;
import net.hugmesh.commons.security.DomainRegistry;
import net.hugmesh.commons.security.PrincipalDomain;
import net.hugmesh.adminbff.web.ApiExceptionHandler;
import net.hugmesh.adminbff.web.ValidationExceptionHandler;

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
 * The admin install-request inbox controller role matrix — ADMIN/SUPERADMIN ALLOW (list +
 * decide), MOD/USER DENY, and the unknown-status -> 400 guard.
 */
@WebFluxTest(controllers = DesktopInstallRequestAdminController.class)
@Import({SecurityConfig.class, DomainRegistry.class, ValidationExceptionHandler.class, ApiExceptionHandler.class})
class DesktopInstallRequestAdminControllerTest {

    @Autowired ApplicationContext context;

    WebTestClient web;

    @BeforeEach
    void setUpWebTestClient() {
        web = WebTestClient.bindToApplicationContext(context).apply(springSecurity()).build();
    }

    @MockitoBean DesktopInstallRequestService service;
    @MockitoBean ReactiveJwtDecoder jwtDecoder;
    @MockitoBean net.hugmesh.authcore.provision.GatewayRevocationClient revocations;

    private WebTestClient asAdmin() {
        return web.mutateWith(mockJwt().authorities(
                new SimpleGrantedAuthority("ROLE_USER"), new SimpleGrantedAuthority("ROLE_ADMIN")));
    }

    private WebTestClient asMod() {
        return web.mutateWith(mockJwt().authorities(
                new SimpleGrantedAuthority("ROLE_USER"), new SimpleGrantedAuthority("ROLE_MOD")));
    }

    private WebTestClient asUser() {
        return web.mutateWith(mockJwt().authorities(new SimpleGrantedAuthority("ROLE_USER")));
    }

    private static DesktopInstallRequest req() {
        return new DesktopInstallRequest("r1", "alice", "a.ref", "dev-1",
                DesktopInstallRequest.STATUS_PENDING, null, null, "brandx", Instant.now());
    }

    @Test
    void list_asAdmin_isAllowed() {
        when(service.listForAdmin(any(PrincipalDomain.class))).thenReturn(Flux.just(req()));
        asAdmin().get().uri("/bff/admin/desktop/install-requests")
                .exchange().expectStatus().isOk()
                .expectBody().jsonPath("$[0].requester").isEqualTo("alice");
    }

    @Test
    void decide_approve_asAdmin_isAllowed() {
        when(service.decide(eq("r1"), eq("approved"), anyString(), any(PrincipalDomain.class)))
                .thenReturn(Mono.just(1L));
        asAdmin().post().uri("/bff/admin/desktop/install-requests/r1/decide?status=approved")
                .exchange().expectStatus().isOk()
                .expectBody().jsonPath("$.decided").isEqualTo(1)
                .jsonPath("$.status").isEqualTo("approved");
        verify(service).decide(eq("r1"), eq("approved"), anyString(), any(PrincipalDomain.class));
    }

    @Test
    void decide_unknownStatus_isBadRequest_andNeverDecides() {
        asAdmin().post().uri("/bff/admin/desktop/install-requests/r1/decide?status=bogus")
                .exchange().expectStatus().isBadRequest();
        verify(service, never()).decide(anyString(), anyString(), anyString(), any());
    }

    // ── MOD / USER DENY ──────────────────────────────────────────────────────────

    @Test
    void list_asUser_isForbidden() {
        asUser().get().uri("/bff/admin/desktop/install-requests")
                .exchange().expectStatus().isForbidden();
    }

    @Test
    void decide_asMod_isForbidden_andNeverDecides() {
        asMod().post().uri("/bff/admin/desktop/install-requests/r1/decide?status=approved")
                .exchange().expectStatus().isForbidden();
        verify(service, never()).decide(anyString(), anyString(), anyString(), any());
    }
}
