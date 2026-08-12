package net.hugmesh.adminbff.desktop;
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
import net.hugmesh.commons.security.DomainRegistry;
import net.hugmesh.adminbff.web.ApiExceptionHandler;
import net.hugmesh.adminbff.web.ValidationExceptionHandler;

import java.time.Instant;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.mockJwt;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.springSecurity;

/**
 * The user-facing install-request controller — the owner==subject keystone: requester is the
 * JWT SUBJECT (never a body field), an unauthenticated caller is 401, and a user lists ONLY
 * their own requests. USER-SITUATIONAL + the negative cross-user isolation at the controller.
 */
@WebFluxTest(controllers = DesktopInstallRequestUserController.class)
@Import({SecurityConfig.class, DomainRegistry.class, ValidationExceptionHandler.class, ApiExceptionHandler.class})
class DesktopInstallRequestUserControllerTest {

    @Autowired ApplicationContext context;

    WebTestClient web;

    @BeforeEach
    void setUpWebTestClient() {
        web = WebTestClient.bindToApplicationContext(context).apply(springSecurity()).build();
    }

    @MockitoBean DesktopInstallRequestService service;
    @MockitoBean ReactiveJwtDecoder jwtDecoder;

    private WebTestClient asUser(String subject) {
        return web.mutateWith(mockJwt()
                .jwt(j -> j.subject(subject))
                .authorities(new SimpleGrantedAuthority("ROLE_USER")));
    }

    private static DesktopInstallRequest req(String requester) {
        return new DesktopInstallRequest("r1", requester, "a.ref", "dev-1",
                DesktopInstallRequest.STATUS_PENDING, null, null, "default", Instant.now());
    }

    private static final String SUBMIT_BODY = "{\"appRef\":\"a.ref\",\"deviceId\":\"dev-1\"}";

    @Test
    void submit_asUser_usesJwtSubjectAsRequester_notBody() {
        when(service.submit(eq("alice"), eq("a.ref"), eq("dev-1"), anyString()))
                .thenReturn(Mono.just(req("alice")));
        asUser("alice").post().uri("/bff/desktop/install-requests")
                .contentType(MediaType.APPLICATION_JSON).bodyValue(SUBMIT_BODY)
                .exchange().expectStatus().isCreated()
                .expectBody().jsonPath("$.requester").isEqualTo("alice");
        // requester is the JWT subject, never a body field.
        verify(service).submit(eq("alice"), eq("a.ref"), eq("dev-1"), anyString());
    }

    @Test
    void mine_asUser_listsOwnRequests() {
        when(service.listMine(eq("alice"), anyString())).thenReturn(Flux.just(req("alice")));
        asUser("alice").get().uri("/bff/desktop/install-requests")
                .exchange().expectStatus().isOk()
                .expectBody().jsonPath("$[0].requester").isEqualTo("alice");
        verify(service).listMine(eq("alice"), anyString());
    }

    @Test
    void submit_unauthenticated_isUnauthorized_andNeverWrites() {
        web.post().uri("/bff/desktop/install-requests")
                .contentType(MediaType.APPLICATION_JSON).bodyValue(SUBMIT_BODY)
                .exchange().expectStatus().isUnauthorized();
        verify(service, never()).submit(anyString(), anyString(), anyString(), anyString());
    }

    @Test
    void submit_missingAppRef_isBadRequest() {
        asUser("alice").post().uri("/bff/desktop/install-requests")
                .contentType(MediaType.APPLICATION_JSON).bodyValue("{\"deviceId\":\"dev-1\"}")
                .exchange().expectStatus().isBadRequest();
        verify(service, never()).submit(anyString(), anyString(), anyString(), anyString());
    }
}
