package systems.hugmesh.adminbff;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webflux.test.autoconfigure.WebFluxTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.reactive.server.WebTestClient;
import reactor.core.publisher.Mono;
import systems.hugmesh.adminbff.account.AccountLocalpartService;
import systems.hugmesh.adminbff.config.SecurityConfig;
import systems.hugmesh.adminbff.locallogin.LocalLoginRateLimiter;
import systems.hugmesh.adminbff.profile.ProfileForwarder;
import systems.hugmesh.adminbff.provision.ServiceTokenBroker;
import systems.hugmesh.adminbff.suspension.SuspensionService;
import systems.hugmesh.adminbff.usage.UsageService;
import systems.hugmesh.authcore.account.Account;
import systems.hugmesh.authcore.account.AccountStatus;
import systems.hugmesh.authcore.account.AccountStore;
import systems.hugmesh.authcore.casdoor.MfaChallengeService;
import systems.hugmesh.authcore.config.SessionCookieService;
import systems.hugmesh.authcore.provision.GatewayRevocationClient;

import java.util.List;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.mockJwt;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.springSecurity;

/**
 * Pure HTTP-layer {@code @WebFluxTest} slice for {@link AuthController} — all
 * dependencies are mocked, so no database or Testcontainers is required.
 *
 * <p>Covers the four contract cases called out in the auth-coverage audit:
 * <ol>
 *   <li>{@code POST /bff/login} with a registered account → 200 + session token in body</li>
 *   <li>{@code POST /bff/login} for an account that does not exist → 401</li>
 *   <li>{@code GET /bff/me} with a valid JWT (email claim resolves account) → 200 + id/roles</li>
 *   <li>{@code GET /bff/me} with no credential → 401 from the filter chain</li>
 * </ol>
 *
 * <p>The {@link AccountStore} is fully mocked here (unlike {@link AuthControllerTest}
 * which drives a real durable store over Testcontainers Postgres). That trade-off is
 * intentional: these four tests exist to catch HTTP-layer regressions (status codes,
 * JSON field presence, security filter wiring) without coupling to schema details.
 * Behavioural correctness of the store + session lifecycle is the remit of
 * {@link AuthControllerTest} and the {@code @DataR2dbcTest} repository slices.
 */
@WebFluxTest(controllers = AuthController.class)
@Import({SecurityConfig.class, systems.hugmesh.commons.security.DomainRegistry.class,
        LocalLoginRateLimiter.class})
class AuthControllerWebFluxTest {

    // ── All controller dependencies are mocked ──────────────────────────

    @MockitoBean AccountStore store;
    @MockitoBean AccountLocalpartService localparts;
    @MockitoBean ServiceTokenBroker broker;
    @MockitoBean UsageService usage;
    @MockitoBean SuspensionService suspensions;
    @MockitoBean ProfileForwarder profiles;
    @MockitoBean GatewayRevocationClient revocations;
    @MockitoBean MfaChallengeService mfaChallenge;
    @MockitoBean ReactiveJwtDecoder jwtDecoder;

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

    // ── Fixture account and token ───────────────────────────────────────

    private static final String EMAIL = "alice@hugmesh.systems";
    private static final String ACCOUNT_ID = "google:" + EMAIL;
    private static final String SESSION_TOKEN = "bff_test_token_abc123";

    private static final Account ALICE = new Account(
            ACCOUNT_ID, "google", EMAIL, true, List.of("user", "admin"));

    @BeforeEach
    void setUp() {
        web = WebTestClient.bindToApplicationContext(context).apply(springSecurity()).build();

        // Default stubs shared across tests — individual tests override where needed.
        when(usage.record(anyString(), any(), anyString())).thenReturn(Mono.empty());
        when(suspensions.statusFor(anyString())).thenReturn(Mono.just(AccountStatus.active()));
        when(profiles.forward(anyString(), any(), any())).thenReturn(Mono.empty());

        // /bff/me: the opaque-token path (store.sessionOf) returns empty so resolution
        // falls through to the JWT path (accountFromJwt). The JWT path calls
        // store.account(idFor("google", email)).
        when(store.sessionOf(any())).thenReturn(Mono.empty());
        when(store.account(ACCOUNT_ID)).thenReturn(Mono.just(ALICE));

        // login path: store.account resolves the registered account.
        when(store.newSession(ALICE)).thenReturn(Mono.just(SESSION_TOKEN));
    }

    // ── Test 1: POST /bff/login — valid registered account → 200 ───────

    /**
     * A registered google account exists in the store. The login endpoint is
     * {@code permitAll} (no Casdoor JWT required — the caller is pre-token). The
     * response must be 200 with a {@code token} field, the account {@code id}, the
     * {@code provider}, the {@code roles} array, {@code registrationComplete}, and
     * a {@code status} of "active".
     */
    @Test
    void login_registeredAccount_returns200WithSessionToken() {
        web.post().uri("/bff/login")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"email\":\"" + EMAIL + "\",\"provider\":\"google\"}")
                .exchange()
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$.token").isEqualTo(SESSION_TOKEN)
                .jsonPath("$.id").isEqualTo(ACCOUNT_ID)
                .jsonPath("$.provider").isEqualTo("google")
                .jsonPath("$.roles").isArray()
                .jsonPath("$.registrationComplete").isEqualTo(true)
                .jsonPath("$.status").isEqualTo("active");
    }

    // ── Test 2: POST /bff/login — no account → 401 ─────────────────────

    /**
     * No account row exists for the given email (store.account returns empty). The
     * controller must surface a 401 with {@code {"error":"no account — register first"}}.
     * This mirrors the pre-registration case where someone tries to log in before the
     * admin has registered them.
     */
    @Test
    void login_noAccount_returns401WithErrorBody() {
        String unknown = "nobody@external.com";
        when(store.account(AccountStore.idFor("google", unknown))).thenReturn(Mono.empty());

        web.post().uri("/bff/login")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"email\":\"" + unknown + "\",\"provider\":\"google\"}")
                .exchange()
                .expectStatus().isUnauthorized()
                .expectBody()
                .jsonPath("$.error").isEqualTo("no account — register first");
    }

    // ── Test 3: GET /bff/me — authenticated via JWT → 200 ──────────────

    /**
     * The caller presents a valid Casdoor JWT with an {@code email} claim. The
     * resource-server chain authenticates the request; the controller resolves the
     * account from the JWT email via {@code store.account(idFor("google", email))}.
     * The response must be 200 with the correct {@code id}, {@code provider},
     * {@code roles} array, and {@code registrationComplete} flag.
     *
     * <p>{@code mockJwt()} short-circuits the real {@link ReactiveJwtDecoder} and
     * installs a synthetic {@link org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken}
     * in the security context, which is what the controller's {@code accountFromJwt}
     * helper reads.
     */
    @Test
    void me_authenticatedWithJwt_returns200WithUserInfo() {
        web.mutateWith(mockJwt().jwt(j -> j.claim("email", EMAIL)))
                .get().uri("/bff/me")
                .exchange()
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$.id").isEqualTo(ACCOUNT_ID)
                .jsonPath("$.provider").isEqualTo("google")
                .jsonPath("$.roles").isArray()
                .jsonPath("$.registrationComplete").isEqualTo(true)
                .jsonPath("$.status").isEqualTo("active");
    }

    // ── Test 4: GET /bff/me — no credential → 401 ──────────────────────

    /**
     * No {@code Authorization} header and no session cookie are present. The
     * resource-server security filter chain rejects the request before it reaches the
     * controller — the response must be 401 (Spring Security's default 401 body).
     * This validates that {@code /bff/me} is NOT accidentally marked {@code permitAll}.
     */
    @Test
    void me_unauthenticated_returns401FromFilterChain() {
        web.get().uri("/bff/me")
                .exchange()
                .expectStatus().isUnauthorized();
    }
}
