package systems.hugmesh.adminbff.casdoor;
import systems.hugmesh.authcore.casdoor.*;
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
import systems.hugmesh.adminbff.config.SecurityConfig;
import systems.hugmesh.commons.security.DomainRegistry;
import systems.hugmesh.adminbff.web.ApiExceptionHandler;
import systems.hugmesh.adminbff.web.ValidationExceptionHandler;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.mockJwt;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.springSecurity;

/**
 * Slice test for {@code POST /bff/mfa/challenge} ({@link MfaChallengeController}). Covers
 * the ships-dark 503 (mirrors {@code DesktopStepUpController}) + subject-from-JWT-not-body
 * + the verified/unverified result mapping. The dual-stamp itself is unit-tested in
 * {@link MfaChallengeServiceTest}; here the service is mocked.
 */
@WebFluxTest(controllers = MfaChallengeController.class)
@Import({SecurityConfig.class, DomainRegistry.class,
        ValidationExceptionHandler.class, ApiExceptionHandler.class})
class MfaChallengeControllerTest {

    private static final String URI = "/bff/mfa/challenge";

    @Autowired ApplicationContext context;

    WebTestClient web;

    @BeforeEach
    void setUpWebTestClient() {
        web = WebTestClient.bindToApplicationContext(context).apply(springSecurity()).build();
    }

    @MockitoBean MfaChallengeService service;
    @MockitoBean ReactiveJwtDecoder jwtDecoder;

    private WebTestClient asUser(String subject, String name) {
        return web.mutateWith(mockJwt()
                .jwt(j -> j.subject(subject).claim("name", name))
                .authorities(new SimpleGrantedAuthority("ROLE_USER")));
    }

    private static String body(String factor, String credential) {
        return "{\"factor\":\"" + factor + "\",\"credential\":\"" + credential + "\"}";
    }

    @Test
    void whileDark_is503_andNeverChallenges() {
        when(service.enabled()).thenReturn(false);
        asUser("sub-x", "alice").post().uri(URI)
                .contentType(MediaType.APPLICATION_JSON).bodyValue(body("totp", "123456"))
                .exchange().expectStatus().isEqualTo(503)
                .expectBody().jsonPath("$.error")
                .value(org.hamcrest.Matchers.containsString("ships dark"));
        verify(service, never()).challenge(anyString(), any(), any(), any(), anyString());
    }

    @Test
    void enabled_verifiedFactor_returnsMfaSatisfied_subjectFromJwtNotBody() {
        when(service.enabled()).thenReturn(true);
        when(service.challenge(eq("sub-x"), eq("alice"), any(), eq(MfaFactorVerifier.Factor.TOTP), eq("123456")))
                .thenReturn(Mono.just(true));

        // The body carries NO subject — even if a caller tried, the controller passes the
        // JWT subject ("sub-x"), never a body field, to the service.
        asUser("sub-x", "alice").post().uri(URI)
                .contentType(MediaType.APPLICATION_JSON).bodyValue(body("totp", "123456"))
                .exchange().expectStatus().isOk()
                .expectBody().jsonPath("$.mfaSatisfied").isEqualTo(true);

        verify(service).challenge(eq("sub-x"), eq("alice"), any(), eq(MfaFactorVerifier.Factor.TOTP), eq("123456"));
    }

    @Test
    void enabled_unverifiedFactor_is401() {
        when(service.enabled()).thenReturn(true);
        when(service.challenge(anyString(), any(), any(), any(), anyString()))
                .thenReturn(Mono.just(false));
        asUser("sub-x", "alice").post().uri(URI)
                .contentType(MediaType.APPLICATION_JSON).bodyValue(body("totp", "wrong"))
                .exchange().expectStatus().isUnauthorized();
    }

    @Test
    void enabled_unknownFactor_is400() {
        when(service.enabled()).thenReturn(true);
        asUser("sub-x", "alice").post().uri(URI)
                .contentType(MediaType.APPLICATION_JSON).bodyValue(body("smoke-signal", "x"))
                .exchange().expectStatus().isBadRequest();
        verify(service, never()).challenge(anyString(), any(), any(), any(), anyString());
    }

    @Test
    void blankFactor_is400_validation() {
        when(service.enabled()).thenReturn(true);
        asUser("sub-x", "alice").post().uri(URI)
                .contentType(MediaType.APPLICATION_JSON).bodyValue("{\"factor\":\"\",\"credential\":\"x\"}")
                .exchange().expectStatus().isBadRequest();
    }

    @Test
    void unauthenticated_is401() {
        when(service.enabled()).thenReturn(true);
        web.post().uri(URI)
                .contentType(MediaType.APPLICATION_JSON).bodyValue(body("totp", "123456"))
                .exchange().expectStatus().isUnauthorized();
    }
}
