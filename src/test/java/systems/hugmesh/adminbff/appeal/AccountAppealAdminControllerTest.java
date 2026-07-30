package systems.hugmesh.adminbff.appeal;

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
import systems.hugmesh.adminbff.config.SecurityConfig;
import systems.hugmesh.commons.security.DomainRegistry;
import systems.hugmesh.commons.security.PrincipalDomain;
import systems.hugmesh.adminbff.web.ApiExceptionHandler;
import systems.hugmesh.adminbff.web.ValidationExceptionHandler;

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
 * The admin account-appeal inbox controller role matrix — ADMIN/SUPERADMIN ALLOW (list +
 * decide), MOD/USER DENY (MOD is deliberately excluded — see the controller javadoc: MOD
 * cannot ban/unban an account, so it must not be able to approve an appeal against one),
 * and the unknown-status -> 400 guard.
 */
@WebFluxTest(controllers = AccountAppealAdminController.class)
@Import({SecurityConfig.class, DomainRegistry.class, ValidationExceptionHandler.class, ApiExceptionHandler.class})
class AccountAppealAdminControllerTest {

    @Autowired ApplicationContext context;

    WebTestClient web;

    @BeforeEach
    void setUpWebTestClient() {
        web = WebTestClient.bindToApplicationContext(context).apply(springSecurity()).build();
    }

    @MockitoBean AccountAppealService service;
    @MockitoBean ReactiveJwtDecoder jwtDecoder;

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

    private static AccountAppeal appeal() {
        return new AccountAppeal("ap1", "google:alice@x.com", "alice@x.com", "brandx",
                "let me back in", null, AccountAppeal.STATUS_PENDING, Instant.now(), null, null);
    }

    @Test
    void list_asAdmin_isAllowed() {
        when(service.listForAdmin(any(PrincipalDomain.class))).thenReturn(Flux.just(appeal()));
        asAdmin().get().uri("/bff/admin/account-appeals")
                .exchange().expectStatus().isOk()
                .expectBody().jsonPath("$[0].userSub").isEqualTo("google:alice@x.com");
    }

    @Test
    void decide_approve_asAdmin_isAllowed() {
        when(service.decide(eq("ap1"), eq("APPROVED"), anyString(), any(PrincipalDomain.class)))
                .thenReturn(Mono.just(1L));
        asAdmin().post().uri("/bff/admin/account-appeals/ap1/decide?status=APPROVED")
                .exchange().expectStatus().isOk()
                .expectBody().jsonPath("$.decided").isEqualTo(1)
                .jsonPath("$.status").isEqualTo("APPROVED");
        verify(service).decide(eq("ap1"), eq("APPROVED"), anyString(), any(PrincipalDomain.class));
    }

    @Test
    void decide_approve_whenRestoreFails_propagatesError_andNeverRendersApplied() {
        when(service.decide(eq("ap1"), eq("APPROVED"), anyString(), any(PrincipalDomain.class)))
                .thenReturn(Mono.error(new RuntimeException("clear failed")));
        asAdmin().post().uri("/bff/admin/account-appeals/ap1/decide?status=APPROVED")
                .exchange().expectStatus().is5xxServerError();
    }

    @Test
    void decide_unknownStatus_isBadRequest_andNeverDecides() {
        asAdmin().post().uri("/bff/admin/account-appeals/ap1/decide?status=bogus")
                .exchange().expectStatus().isBadRequest();
        verify(service, never()).decide(anyString(), anyString(), anyString(), any());
    }

    // ── MOD / USER DENY ──────────────────────────────────────────────────────────

    @Test
    void list_asUser_isForbidden() {
        asUser().get().uri("/bff/admin/account-appeals")
                .exchange().expectStatus().isForbidden();
    }

    @Test
    void decide_asMod_isForbidden_andNeverDecides() {
        asMod().post().uri("/bff/admin/account-appeals/ap1/decide?status=APPROVED")
                .exchange().expectStatus().isForbidden();
        verify(service, never()).decide(anyString(), anyString(), anyString(), any());
    }
}
