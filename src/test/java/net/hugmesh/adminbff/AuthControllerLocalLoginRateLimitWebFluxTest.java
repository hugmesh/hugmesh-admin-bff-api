package net.hugmesh.adminbff;

import org.junit.jupiter.api.BeforeEach;
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
import reactor.core.publisher.Mono;
import net.hugmesh.adminbff.account.AccountLocalpartService;
import net.hugmesh.adminbff.config.SecurityConfig;
import net.hugmesh.adminbff.locallogin.LocalLoginRateLimiter;
import net.hugmesh.adminbff.locallogin.LocalSecretVerifier;
import net.hugmesh.adminbff.profile.ProfileForwarder;
import net.hugmesh.adminbff.provision.ServiceTokenBroker;
import net.hugmesh.adminbff.suspension.SuspensionService;
import net.hugmesh.adminbff.usage.UsageService;
import net.hugmesh.authcore.account.AccountStore;
import net.hugmesh.authcore.casdoor.MfaChallengeService;
import net.hugmesh.authcore.config.SessionCookieService;
import net.hugmesh.authcore.provision.GatewayRevocationClient;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.springSecurity;

/**
 * {@code @WebFluxTest} slice proving {@code POST /bff/login/local} throttles BEFORE
 * {@link LocalSecretVerifier#verify} is ever called (PR #198 security review, MEDIUM finding —
 * see {@link LocalLoginRateLimiter} for the full rationale). {@link LocalLoginRateLimiter} is
 * MOCKED here (its own scoping/window behaviour is covered directly by
 * {@code LocalLoginRateLimiterTest}) so this class can assert the controller's WIRING in
 * isolation: an allowed request reaches {@code verify()}; a throttled request returns 429 and
 * NEVER invokes {@code verify()}.
 */
@WebFluxTest(controllers = AuthController.class)
@Import({SecurityConfig.class, net.hugmesh.commons.security.DomainRegistry.class})
class AuthControllerLocalLoginRateLimitWebFluxTest {

    @MockitoBean AccountStore store;
    @MockitoBean AccountLocalpartService localparts;
    @MockitoBean ServiceTokenBroker broker;
    @MockitoBean UsageService usage;
    @MockitoBean SuspensionService suspensions;
    @MockitoBean ProfileForwarder profiles;
    @MockitoBean GatewayRevocationClient revocations;
    @MockitoBean MfaChallengeService mfaChallenge;
    @MockitoBean ReactiveJwtDecoder jwtDecoder;
    @MockitoBean LocalSecretVerifier localSecretVerifier;
    @MockitoBean LocalLoginRateLimiter localLoginRateLimiter;

    @Autowired ApplicationContext context;
    WebTestClient web;

    /** A2 cookie service with cookie mode OFF (ships dark — the token stays in the body). */
    @TestConfiguration
    static class Cfg {
        @Bean
        SessionCookieService sessionCookieService() {
            return new SessionCookieService(false, true, null);
        }
    }

    private static final String USERNAME = "brandowner@acme.local";
    private static final String SECRET = "s3cret-handoff";

    @BeforeEach
    void setUp() {
        web = WebTestClient.bindToApplicationContext(context).apply(springSecurity()).build();
        when(usage.record(anyString(), any(), anyString())).thenReturn(Mono.empty());
    }

    private WebTestClient.ResponseSpec post() {
        String body = "{\"roleId\":\"brandowner\",\"username\":\"" + USERNAME + "\",\"secret\":\"" + SECRET + "\"}";
        return web.post().uri("/bff/login/local")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(body)
                .exchange();
    }

    /** Under the limit: the request reaches verify() (a bad-secret 401 here just proves the call
     *  was made — the success path is already covered by AuthControllerLocalLoginWebFluxTest). */
    @Test
    void underLimit_passesThroughToVerify() {
        when(localLoginRateLimiter.tryAcquire(any(), eq(USERNAME))).thenReturn(true);
        when(localSecretVerifier.verify(USERNAME, SECRET)).thenReturn(Mono.just(false));

        post().expectStatus().isUnauthorized();

        verify(localSecretVerifier).verify(USERNAME, SECRET);
    }

    /** Over the limit: 429, and verify() is NEVER invoked — the whole point is to stop the
     *  Casdoor-oracle call, not merely decorate it. */
    @Test
    void overLimit_returns429_withoutCallingCasdoor() {
        when(localLoginRateLimiter.tryAcquire(any(), eq(USERNAME))).thenReturn(false);

        post().expectStatus().isEqualTo(429);

        verify(localSecretVerifier, never()).verify(any(), any());
    }
}
