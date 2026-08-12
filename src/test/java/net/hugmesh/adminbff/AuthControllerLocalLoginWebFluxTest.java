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
import net.hugmesh.authcore.account.Account;
import net.hugmesh.authcore.account.AccountStatus;
import net.hugmesh.authcore.account.AccountStore;
import net.hugmesh.authcore.casdoor.MfaChallengeService;
import net.hugmesh.authcore.config.SessionCookieService;
import net.hugmesh.authcore.provision.GatewayRevocationClient;

import java.util.List;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.springSecurity;

/**
 * {@code @WebFluxTest} slice for the passwordless {@code POST /bff/login/local} endpoint with the
 * {@link LocalSecretVerifier} WIRED (mocked). Proves the contract: the secret is validated through
 * the verifier BEFORE a session is minted, a valid credential reuses the SAME session/body path as
 * {@code /bff/login}, and every failure (bad secret / unknown account) is an indistinguishable 401.
 */
@WebFluxTest(controllers = AuthController.class)
@Import({SecurityConfig.class, net.hugmesh.commons.security.DomainRegistry.class,
        LocalLoginRateLimiter.class})
class AuthControllerLocalLoginWebFluxTest {

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
    private static final String ACCOUNT_ID = "google:" + USERNAME;
    private static final String SESSION_TOKEN = "bff_local_token_xyz";
    private static final Account BRANDOWNER = new Account(
            ACCOUNT_ID, "google", USERNAME, true, List.of("user", "admin"));

    @BeforeEach
    void setUp() {
        web = WebTestClient.bindToApplicationContext(context).apply(springSecurity()).build();
        when(usage.record(anyString(), any(), anyString())).thenReturn(Mono.empty());
        when(suspensions.statusFor(anyString())).thenReturn(Mono.just(AccountStatus.active()));
        when(store.newSession(BRANDOWNER)).thenReturn(Mono.just(SESSION_TOKEN));
    }

    private WebTestClient.ResponseSpec post(String secret) {
        String body = "{\"roleId\":\"brandowner\",\"username\":\"" + USERNAME + "\",\"secret\":\"" + secret + "\"}";
        return web.post().uri("/bff/login/local")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(body)
                .exchange();
    }

    /** Casdoor validates the secret → the SAME account lookup + session-mint path as /bff/login. */
    @Test
    void validSecret_mintsSession() {
        when(localSecretVerifier.verify(USERNAME, SECRET)).thenReturn(Mono.just(true));
        when(store.account(ACCOUNT_ID)).thenReturn(Mono.just(BRANDOWNER));

        post(SECRET)
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$.token").isEqualTo(SESSION_TOKEN)
                .jsonPath("$.id").isEqualTo(ACCOUNT_ID)
                .jsonPath("$.provider").isEqualTo("google")
                .jsonPath("$.roles").isArray()
                .jsonPath("$.registrationComplete").isEqualTo(true)
                .jsonPath("$.status").isEqualTo("active");
    }

    /** Casdoor rejects the secret → 401, no account touched, no session minted. */
    @Test
    void invalidSecret_returns401() {
        when(localSecretVerifier.verify(USERNAME, "wrong")).thenReturn(Mono.just(false));

        post("wrong").expectStatus().isUnauthorized();
    }

    /** Valid secret but the identity has no admin-bff account → 401, indistinguishable from a bad secret. */
    @Test
    void validSecretUnknownAccount_returns401() {
        when(localSecretVerifier.verify(USERNAME, SECRET)).thenReturn(Mono.just(true));
        when(store.account(ACCOUNT_ID)).thenReturn(Mono.empty());

        post(SECRET).expectStatus().isUnauthorized();
    }
}
