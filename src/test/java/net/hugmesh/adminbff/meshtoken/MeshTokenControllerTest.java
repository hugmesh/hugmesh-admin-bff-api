package net.hugmesh.adminbff.meshtoken;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webflux.test.autoconfigure.WebFluxTest;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.reactive.server.WebTestClient;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import net.hugmesh.adminbff.config.SecurityConfig;
import net.hugmesh.adminbff.web.ApiExceptionHandler;
import net.hugmesh.adminbff.web.StepUpRequiredException;
import net.hugmesh.adminbff.web.ValidationExceptionHandler;
import net.hugmesh.commons.security.DomainRegistry;
import net.hugmesh.commons.security.PrincipalDomain;

import java.time.Instant;
import java.util.List;
import java.util.Map;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.mockJwt;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.springSecurity;

/**
 * Web-layer contract for {@code /bff/admin/mesh-tokens}: a non-admin is 403 on every verb, an
 * anonymous caller 401, POST needs the step-up (refused through the seam, with the signal header)
 * and is refused BEFORE the service is called, dark answers the 503 descriptor, and the service's
 * refusals map to 403 / 400 / 503. The service is mocked; its rules are {@link MeshTokenServiceTest}.
 */
@WebFluxTest(controllers = MeshTokenController.class)
@Import({SecurityConfig.class, DomainRegistry.class, ValidationExceptionHandler.class, ApiExceptionHandler.class})
class MeshTokenControllerTest {

    private static final String STEP_UP = MeshTokenStepUpGate.STEP_UP_HEADER;
    private static final String BODY = "{\"domain\":\"hugmesh.net\",\"role\":\"admin\",\"shell\":true,"
            + "\"lifetimeSeconds\":3600,\"nodeName\":\"laptop-1\"}";

    @Autowired ApplicationContext context;
    WebTestClient web;

    @MockitoBean MeshTokenService service;
    @MockitoBean MeshTokenStepUpGate stepUp;
    @MockitoBean net.hugmesh.authcore.casdoor.MfaStepUpService mfaStepUp;
    @MockitoBean ReactiveJwtDecoder jwtDecoder;

    @BeforeEach
    void setUp() {
        web = WebTestClient.bindToApplicationContext(context).apply(springSecurity()).build();
        when(mfaStepUp.isFresh(any())).thenReturn(Mono.just(false));
        when(mfaStepUp.consume(any())).thenReturn(Mono.empty());
        when(stepUp.isSatisfied(anyString(), any(), anyBoolean()))
                .thenAnswer(inv -> inv.<Boolean>getArgument(2)
                        || stepUp.isSatisfied(inv.getArgument(0), inv.getArgument(1)));
        when(stepUp.isSatisfied(any(), eq("good"))).thenReturn(true);
        when(service.isEnabled()).thenReturn(true);
    }

    private WebTestClient as(String role) {
        return web.mutateWith(mockJwt()
                .jwt(j -> j.subject("sub-" + role).claim("roles", List.of(role)))
                .authorities(new SimpleGrantedAuthority("ROLE_USER"),
                        new SimpleGrantedAuthority("ROLE_" + role.toUpperCase())));
    }

    private WebTestClient asUser() {
        return web.mutateWith(mockJwt().jwt(j -> j.claim("roles", List.of("user")))
                .authorities(new SimpleGrantedAuthority("ROLE_USER")));
    }

    private WebTestClient.ResponseSpec post(WebTestClient c, String stepUpToken) {
        WebTestClient.RequestBodySpec r = c.post().uri("/bff/admin/mesh-tokens").contentType(MediaType.APPLICATION_JSON);
        if (stepUpToken != null) {
            r = r.header(STEP_UP, stepUpToken);
        }
        return r.bodyValue(BODY).exchange();
    }

    // ── who may call at all ──────────────────────────────────────────────────────────

    @Test
    void user_isForbidden_onEveryVerb() {
        post(asUser(), "good").expectStatus().isForbidden();
        asUser().get().uri("/bff/admin/mesh-tokens/issuer").exchange().expectStatus().isForbidden();
        asUser().get().uri("/bff/admin/mesh-tokens").exchange().expectStatus().isForbidden();
        as("mod").get().uri("/bff/admin/mesh-tokens").exchange().expectStatus().isForbidden();
        verify(service, never()).issue(any(), any(), any());
        verify(service, never()).issuer(any());
        verify(service, never()).list(any());
    }

    @Test
    void anonymous_isUnauthorized() {
        web.post().uri("/bff/admin/mesh-tokens").contentType(MediaType.APPLICATION_JSON).bodyValue(BODY)
                .exchange().expectStatus().isUnauthorized();
        web.get().uri("/bff/admin/mesh-tokens/issuer").exchange().expectStatus().isUnauthorized();
        verify(service, never()).issue(any(), any(), any());
    }

    // ── step-up ─────────────────────────────────────────────────────────────────────

    @Test
    void missingStepUp_isRefusedThroughTheSeam_beforeTheService() {
        post(as("admin"), null).expectStatus().isForbidden()
                .expectHeader().valueEquals(StepUpRequiredException.SIGNAL_HEADER, STEP_UP);
        post(as("superadmin"), "bad").expectStatus().isForbidden()
                .expectHeader().valueEquals(StepUpRequiredException.SIGNAL_HEADER, STEP_UP);
        verify(service, never()).issue(any(), any(), any());
    }

    @Test
    void freshMfa_satisfiesTheStepUp_andIsConsumed() {
        when(mfaStepUp.isFresh(any())).thenReturn(Mono.just(true));
        when(service.issue(any(), any(), any())).thenReturn(Mono.just(result()));
        post(as("admin"), null).expectStatus().isOk();
        verify(mfaStepUp).consume(any());
    }

    // ── outcomes ────────────────────────────────────────────────────────────────────

    @Test
    void issue_returnsTheTokenOnce_withTheRequestPassedThrough() {
        when(service.issue(any(), any(), any())).thenReturn(Mono.just(result()));
        post(as("admin"), "good").expectStatus().isOk()
                .expectBody()
                .jsonPath("$.token").isEqualTo("hugmesh-token-v1.e30.c2ln")
                .jsonPath("$.id").isEqualTo("0123456789abcdef")
                .jsonPath("$.expires").isEqualTo(1762905600)
                .jsonPath("$.fingerprint").isEqualTo(MeshTokenFixtures.FINGERPRINT)
                .jsonPath("$.describe").isEqualTo("admin in hugmesh.net");
        verify(service).issue(eq("sub-admin"), argThat((PrincipalDomain s) -> !s.superadmin()),
                eq(new MeshTokenService.IssueRequest("hugmesh.net", "admin", true, 3600L, "laptop-1")));
    }

    @Test
    void superadmin_reachesTheServiceUnscoped() {
        when(service.issue(any(), any(), any())).thenReturn(Mono.just(result()));
        post(as("superadmin"), "good").expectStatus().isOk();
        verify(service).issue(eq("sub-superadmin"), argThat(PrincipalDomain::superadmin), any());
    }

    @Test
    void dark_isThe503Descriptor() {
        when(service.issue(any(), any(), any())).thenReturn(Mono.error(new MeshTokenService.MeshTokenDarkException()));
        post(as("superadmin"), "good").expectStatus().isEqualTo(503)
                .expectBody().jsonPath("$.dark").isEqualTo(true)
                .jsonPath("$.note").isEqualTo(MeshTokenService.DARK_NOTE)
                .jsonPath("$.token").doesNotExist();
    }

    @Test
    void serviceRefusals_mapTo403_400_503() {
        when(service.issue(any(), any(), any()))
                .thenReturn(Mono.error(new MeshTokenService.MeshTokenDeniedException("Only a superadmin can issue a superadmin token.")));
        post(as("admin"), "good").expectStatus().isForbidden()
                .expectHeader().doesNotExist(StepUpRequiredException.SIGNAL_HEADER);
        when(service.issue(any(), any(), any()))
                .thenReturn(Mono.error(new MeshTokenService.MeshTokenInvalidException("bad role")));
        post(as("admin"), "good").expectStatus().isBadRequest();
        when(service.issue(any(), any(), any()))
                .thenReturn(Mono.error(new HeadscalePreAuthKeyClient.HeadscaleUnavailableException("headscale did not answer in time.")));
        post(as("admin"), "good").expectStatus().isEqualTo(503);
    }

    @Test
    void malformedBody_is400_beforeTheService() {
        as("superadmin").post().uri("/bff/admin/mesh-tokens").contentType(MediaType.APPLICATION_JSON)
                .header(STEP_UP, "good").bodyValue("{\"role\":\"admin\"}").exchange().expectStatus().isBadRequest();
        verify(service, never()).issue(any(), any(), any());
    }

    @Test
    void issuerAndList_areOpenToAdminAndSuperadmin_andCarryNoSecret() {
        when(service.issuer(any())).thenReturn(Map.of("enabled", true, "fingerprint", MeshTokenFixtures.FINGERPRINT));
        when(service.list(any())).thenReturn(Flux.just(new MeshTokenIssued("0123456789abcdef", "hugmesh-local",
                "hugmesh.net", "admin", true, "https://hs.hugmesh.net:8488", MeshTokenFixtures.FINGERPRINT, "17",
                "laptop-1", "sub-admin", Instant.parse("2026-11-04T12:00:00Z"), Instant.parse("2026-11-11T12:00:00Z"))));
        as("admin").get().uri("/bff/admin/mesh-tokens/issuer").exchange().expectStatus().isOk()
                .expectBody().jsonPath("$.fingerprint").isEqualTo(MeshTokenFixtures.FINGERPRINT);
        as("superadmin").get().uri("/bff/admin/mesh-tokens").exchange().expectStatus().isOk()
                .expectBody()
                .jsonPath("$.enabled").isEqualTo(true)
                .jsonPath("$.issued[0].id").isEqualTo("0123456789abcdef")
                .jsonPath("$.issued[0].preauthKeyId").isEqualTo("17")
                .jsonPath("$.issued[0].token").doesNotExist()
                .jsonPath("$.issued[0].authKey").doesNotExist();
    }

    private static MeshTokenService.IssueResult result() {
        return new MeshTokenService.IssueResult("hugmesh-token-v1.e30.c2ln", "0123456789abcdef", 1762905600L,
                MeshTokenFixtures.FINGERPRINT, "admin in hugmesh.net");
    }
}
