package net.hugmesh.adminbff.appeal;

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
import net.hugmesh.authcore.account.Account;
import net.hugmesh.authcore.account.AccountStore;
import net.hugmesh.commons.security.DomainRegistry;
import net.hugmesh.adminbff.web.ApiExceptionHandler;
import net.hugmesh.adminbff.web.ValidationExceptionHandler;

import java.time.Instant;
import java.util.List;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.nullable;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.mockJwt;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.springSecurity;

/**
 * The self-service appeal controller — the owner==subject keystone: userSub/handle are
 * resolved from the caller's OWN account (never body fields), an unauthenticated caller
 * is 401, and a user lists ONLY their own appeals (ALLOW+DENY pair on reachability). Also
 * proves a CURTAILED-but-still-authenticated session (a bare ROLE_USER JWT, no ROLE_ADMIN/
 * ROLE_MOD) reaches this endpoint — the whole point of this surface.
 */
@WebFluxTest(controllers = AccountAppealUserController.class)
@Import({SecurityConfig.class, DomainRegistry.class, ValidationExceptionHandler.class, ApiExceptionHandler.class})
class AccountAppealUserControllerTest {

    @Autowired ApplicationContext context;

    WebTestClient web;

    @BeforeEach
    void setUpWebTestClient() {
        web = WebTestClient.bindToApplicationContext(context).apply(springSecurity()).build();
    }

    @MockitoBean AccountAppealService service;
    @MockitoBean AccountStore store;
    @MockitoBean ReactiveJwtDecoder jwtDecoder;

    private WebTestClient asUser(String email) {
        return web.mutateWith(mockJwt()
                .jwt(j -> j.subject(email).claim("email", email))
                .authorities(new SimpleGrantedAuthority("ROLE_USER")));
    }

    private static Account account(String email) {
        return new Account("google:" + email, "google", email, true, List.of("user"));
    }

    private static AccountAppeal appeal(String userSub) {
        return new AccountAppeal("ap1", userSub, "alice@x.com", "default", "let me back in",
                null, AccountAppeal.STATUS_PENDING, Instant.now(), null, null);
    }

    private static final String SUBMIT_BODY = "{\"reason\":\"let me back in\"}";

    @Test
    void submit_asCurtailedUser_usesResolvedAccountAsOwner_notBody() {
        when(store.sessionOf(nullable(String.class))).thenReturn(Mono.empty());
        when(store.account(eq("google:alice@x.com"))).thenReturn(Mono.just(account("alice@x.com")));
        when(service.submit(eq("google:alice@x.com"), eq("alice@x.com"), anyString(), eq("let me back in"), eq(null)))
                .thenReturn(Mono.just(appeal("google:alice@x.com")));

        asUser("alice@x.com").post().uri("/bff/me/appeal")
                .contentType(MediaType.APPLICATION_JSON).bodyValue(SUBMIT_BODY)
                .exchange().expectStatus().isCreated()
                .expectBody().jsonPath("$.userSub").isEqualTo("google:alice@x.com");
        // owner is the JWT-resolved account, never a body field.
        verify(service).submit(eq("google:alice@x.com"), eq("alice@x.com"), anyString(), eq("let me back in"), eq(null));
    }

    @Test
    void mine_asUser_listsOwnAppeals() {
        when(store.sessionOf(nullable(String.class))).thenReturn(Mono.empty());
        when(store.account(eq("google:alice@x.com"))).thenReturn(Mono.just(account("alice@x.com")));
        when(service.listMine(eq("google:alice@x.com"), anyString())).thenReturn(Flux.just(appeal("google:alice@x.com")));

        asUser("alice@x.com").get().uri("/bff/me/appeal")
                .exchange().expectStatus().isOk()
                .expectBody().jsonPath("$[0].userSub").isEqualTo("google:alice@x.com");
        verify(service).listMine(eq("google:alice@x.com"), anyString());
    }

    @Test
    void submit_unauthenticated_isUnauthorized_andNeverWrites() {
        web.post().uri("/bff/me/appeal")
                .contentType(MediaType.APPLICATION_JSON).bodyValue(SUBMIT_BODY)
                .exchange().expectStatus().isUnauthorized();
        verify(service, never()).submit(anyString(), anyString(), anyString(), anyString(), anyString());
    }

    @Test
    void submit_missingReason_isBadRequest() {
        asUser("alice@x.com").post().uri("/bff/me/appeal")
                .contentType(MediaType.APPLICATION_JSON).bodyValue("{}")
                .exchange().expectStatus().isBadRequest();
        verify(service, never()).submit(anyString(), anyString(), anyString(), anyString(), anyString());
    }
}
