package systems.hugmesh.adminbff.mfa;
import systems.hugmesh.authcore.mfa.*;
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
import systems.hugmesh.authcore.casdoor.MfaStepUpService;
import systems.hugmesh.adminbff.config.SecurityConfig;
import systems.hugmesh.commons.security.DomainRegistry;
import systems.hugmesh.adminbff.web.ApiExceptionHandler;
import systems.hugmesh.adminbff.web.ValidationExceptionHandler;

import java.time.Instant;
import java.util.List;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.mockJwt;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.springSecurity;

/**
 * Slice test for the {@link MfaEnrollmentController}. Covers the ships-dark 503 on every
 * endpoint (mirrors {@code MfaChallengeController}), owner-from-JWT (never a body field), and
 * the STEP-UP gate on factor mutation (DELETE / recovery-regenerate are 403 without a fresh
 * MFA stamp). The service is mocked; the service's behaviour is covered by the R2DBC slices.
 */
@WebFluxTest(controllers = MfaEnrollmentController.class)
@Import({SecurityConfig.class, DomainRegistry.class,
        ValidationExceptionHandler.class, ApiExceptionHandler.class})
class MfaEnrollmentControllerTest {

    @Autowired ApplicationContext context;

    WebTestClient web;

    @BeforeEach
    void setUpWebTestClient() {
        web = WebTestClient.bindToApplicationContext(context).apply(springSecurity()).build();
    }

    @MockitoBean MfaEnrollmentService service;
    @MockitoBean MfaStepUpService stepUp;
    @MockitoBean ReactiveJwtDecoder jwtDecoder;

    private WebTestClient asUser(String subject) {
        return web.mutateWith(mockJwt()
                .jwt(j -> j.subject(subject).claim("name", "alice"))
                .authorities(new SimpleGrantedAuthority("ROLE_USER")));
    }

    @Test
    void enrollTotp_whileDark_is503_andNeverEnrolls() {
        when(stepUp.enabled()).thenReturn(false);
        asUser("sub-x").post().uri("/bff/mfa/enroll/totp")
                .exchange().expectStatus().isEqualTo(503);
        verify(service, never()).beginTotpEnroll(anyString(), any());
    }

    @Test
    void listFactors_whileDark_is503() {
        when(stepUp.enabled()).thenReturn(false);
        asUser("sub-x").get().uri("/bff/mfa/factors")
                .exchange().expectStatus().isEqualTo(503);
    }

    @Test
    void listFactors_enabled_usesJwtSubject_noSecrets() {
        when(stepUp.enabled()).thenReturn(true);
        when(service.listFactors("sub-x")).thenReturn(Flux.just(
                new MfaEnrollmentService.FactorSummary("f1", "TOTP", true, Instant.now())));
        asUser("sub-x").get().uri("/bff/mfa/factors")
                .exchange().expectStatus().isOk()
                .expectBody()
                .jsonPath("$.factors[0].type").isEqualTo("TOTP")
                .jsonPath("$.factors[0].enabled").isEqualTo(true);
        verify(service).listFactors("sub-x");
    }

    @Test
    void removeFactor_withoutFreshStepUp_is403_andNeverRemoves() {
        when(stepUp.enabled()).thenReturn(true);
        when(stepUp.isFresh(any())).thenReturn(Mono.just(false));
        asUser("sub-x").delete().uri("/bff/mfa/factors/f1")
                .exchange().expectStatus().isForbidden();
        verify(service, never()).removeFactor(anyString(), anyString());
    }

    @Test
    void removeFactor_withFreshStepUp_removes_andConsumesFreshness() {
        when(stepUp.enabled()).thenReturn(true);
        when(stepUp.isFresh(any())).thenReturn(Mono.just(true));
        when(stepUp.consume(any())).thenReturn(Mono.empty());
        when(service.removeFactor("sub-x", "f1")).thenReturn(Mono.just(true));
        asUser("sub-x").delete().uri("/bff/mfa/factors/f1")
                .exchange().expectStatus().isOk()
                .expectBody().jsonPath("$.removed").isEqualTo(true);
        verify(service).removeFactor("sub-x", "f1");
        verify(stepUp).consume(any());
    }

    @Test
    void regenerateRecovery_withoutFreshStepUp_is403() {
        when(stepUp.enabled()).thenReturn(true);
        when(stepUp.isFresh(any())).thenReturn(Mono.just(false));
        asUser("sub-x").post().uri("/bff/mfa/recovery/regenerate")
                .exchange().expectStatus().isForbidden();
        verify(service, never()).regenerateRecoveryCodes(anyString());
    }

    @Test
    void verifyTotp_enabled_returnsRecoveryCodesOnce_subjectFromJwt() {
        when(stepUp.enabled()).thenReturn(true);
        when(service.verifyTotpEnroll("sub-x", "123456"))
                .thenReturn(Mono.just(List.of("AAAA-BBBB-CCCC-DDDD")));
        asUser("sub-x").post().uri("/bff/mfa/enroll/totp/verify")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"passcode\":\"123456\"}")
                .exchange().expectStatus().isOk()
                .expectBody()
                .jsonPath("$.enabled").isEqualTo(true)
                .jsonPath("$.recoveryCodes[0]").isEqualTo("AAAA-BBBB-CCCC-DDDD");
        verify(service).verifyTotpEnroll("sub-x", "123456");
    }
}
