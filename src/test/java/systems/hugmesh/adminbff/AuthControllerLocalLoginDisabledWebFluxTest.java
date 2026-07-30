package systems.hugmesh.adminbff;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.webflux.test.autoconfigure.WebFluxTest;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.reactive.server.WebTestClient;
import systems.hugmesh.adminbff.account.AccountLocalpartService;
import systems.hugmesh.adminbff.config.SecurityConfig;
import systems.hugmesh.adminbff.locallogin.LocalLoginRateLimiter;
import systems.hugmesh.adminbff.profile.ProfileForwarder;
import systems.hugmesh.adminbff.provision.ServiceTokenBroker;
import systems.hugmesh.adminbff.suspension.SuspensionService;
import systems.hugmesh.adminbff.usage.UsageService;
import systems.hugmesh.authcore.account.AccountStore;
import systems.hugmesh.authcore.casdoor.MfaChallengeService;
import systems.hugmesh.authcore.config.SessionCookieService;
import systems.hugmesh.authcore.provision.GatewayRevocationClient;

import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.springSecurity;

/**
 * {@code @WebFluxTest} slice for {@code POST /bff/login/local} with NO {@link
 * systems.hugmesh.adminbff.locallogin.LocalSecretVerifier} bean present — i.e. the SHIPS-DARK
 * default ({@code app.local-login.enabled=false}). The controller injects the verifier as
 * {@code @Nullable = null} and the endpoint MUST fail closed (401): no agent secret is ever
 * accepted without a real Casdoor validation. This also proves the AuthController context still
 * loads with the verifier absent (so every other AuthController endpoint is unaffected).
 */
@WebFluxTest(controllers = AuthController.class)
@Import({SecurityConfig.class, systems.hugmesh.commons.security.DomainRegistry.class,
        LocalLoginRateLimiter.class})
class AuthControllerLocalLoginDisabledWebFluxTest {

    @MockitoBean AccountStore store;
    @MockitoBean AccountLocalpartService localparts;
    @MockitoBean ServiceTokenBroker broker;
    @MockitoBean UsageService usage;
    @MockitoBean SuspensionService suspensions;
    @MockitoBean ProfileForwarder profiles;
    @MockitoBean GatewayRevocationClient revocations;
    @MockitoBean MfaChallengeService mfaChallenge;
    @MockitoBean ReactiveJwtDecoder jwtDecoder;
    // NOTE: LocalSecretVerifier is deliberately NOT provided -> injected as @Nullable null.

    @Autowired ApplicationContext context;

    @TestConfiguration
    static class Cfg {
        @Bean
        SessionCookieService sessionCookieService() {
            return new SessionCookieService(false, true, null);
        }
    }

    @Test
    void localLoginDisabled_returns401() {
        WebTestClient web = WebTestClient.bindToApplicationContext(context)
                .apply(springSecurity()).build();
        web.post().uri("/bff/login/local")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"roleId\":\"brandowner\",\"username\":\"brandowner@acme.local\",\"secret\":\"whatever\"}")
                .exchange()
                .expectStatus().isUnauthorized();
    }
}
