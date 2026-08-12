package net.hugmesh.adminbff;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.boot.webflux.test.autoconfigure.WebFluxTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.r2dbc.core.DatabaseClient;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.reactive.server.WebTestClient;
import reactor.core.publisher.Mono;
import net.hugmesh.authcore.account.AccountStore;
import net.hugmesh.adminbff.account.AccountLocalpartRepository;
import net.hugmesh.adminbff.account.AccountLocalpartService;
import net.hugmesh.adminbff.config.SecurityConfig;
import net.hugmesh.authcore.config.SessionCookieService;
import net.hugmesh.authcore.config.SessionCookieWebFilter;
import net.hugmesh.authcore.provision.GatewayRevocationClient;
import net.hugmesh.adminbff.locallogin.LocalLoginRateLimiter;
import net.hugmesh.adminbff.provision.ServiceTokenBroker;
import net.hugmesh.adminbff.support.TestDatabaseConfig;
import net.hugmesh.adminbff.usage.UsageService;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.mockJwt;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.springSecurity;

/**
 * A2 cookie-mode acceptance on {@code AuthController}, SHIPS-DARK default (cookie mode OFF).
 * Proves: the opaque token still rides the response BODY (cookie ships dark — no Set-Cookie),
 * the legacy Bearer header still resolves {@code /bff/me}, the cookie carrier resolves it via
 * the {@link SessionCookieWebFilter} bridge, {@code GET /bff/session} returns the documented
 * shape, and {@code POST /bff/sessionOut} deletes the row + RevocationLists the subject.
 *
 * <p>The {@link SessionCookieWebFilter} is registered as a web filter so the cookie carrier is
 * exercised end-to-end (the {@code @WebFluxTest} slice does not auto-register it).
 */
@WebFluxTest(controllers = AuthController.class)
@Import({SecurityConfig.class, net.hugmesh.commons.security.DomainRegistry.class,
        TestDatabaseConfig.class, SessionCookieWebFilter.class, LocalLoginRateLimiter.class})
class AuthControllerSessionCookieTest {

    @Autowired ApplicationContext context;

    WebTestClient web;
    @Autowired AccountStore store;

    @MockitoBean ServiceTokenBroker broker;
    @MockitoBean UsageService usage;
    @MockitoBean net.hugmesh.adminbff.suspension.SuspensionService suspensions;
    @MockitoBean net.hugmesh.adminbff.profile.ProfileForwarder profiles;
    @MockitoBean GatewayRevocationClient revocations;
    @MockitoBean net.hugmesh.authcore.casdoor.MfaChallengeService mfaChallenge;
    @MockitoBean ReactiveJwtDecoder jwtDecoder;

    @TestConfiguration
    static class Cfg {
        @Bean AccountStore accountStore(DatabaseClient db) {
            AccountStore store = new AccountStore(net.hugmesh.adminbff.testutil.R2dbcRepos.of(db, net.hugmesh.authcore.account.AllowlistRepository.class), net.hugmesh.adminbff.testutil.R2dbcRepos.of(db, net.hugmesh.authcore.account.AccountRowRepository.class), net.hugmesh.adminbff.testutil.R2dbcRepos.of(db, net.hugmesh.authcore.account.BffSessionRepository.class), net.hugmesh.adminbff.testutil.R2dbcRepos.of(db, net.hugmesh.authcore.account.NamespaceGrantRepository.class), "admin@hugmesh.systems");
            store.seedAdmins();
            return store;
        }

        /** Cookie mode OFF (ships dark). */
        @Bean SessionCookieService sessionCookieService() {
            return new SessionCookieService(false, true, null);
        }

        /** The account-takeover-by-collision guard, over the SAME real Testcontainers
         *  Postgres the durable {@code AccountStore} bean above uses. */
        @Bean AccountLocalpartService accountLocalpartService(DatabaseClient db) {
            return new AccountLocalpartService(
                    net.hugmesh.adminbff.testutil.R2dbcRepos.of(db, AccountLocalpartRepository.class));
        }
    }

    @BeforeEach
    void stubs() {
        web = WebTestClient.bindToApplicationContext(context).apply(springSecurity()).build();
        when(suspensions.statusFor(anyString()))
                .thenReturn(Mono.just(net.hugmesh.authcore.account.AccountStatus.active()));
        when(profiles.forward(anyString(), any(), any())).thenReturn(Mono.empty());
        when(usage.record(anyString(), any(), anyString())).thenReturn(Mono.empty());
        when(revocations.revokeCoarse(anyString(), anyString(), anyString(), anyLong()))
                .thenReturn(Mono.empty());
        // Logout clears the advisory Casdoor MFA Property (best-effort, inert when dark).
        when(mfaChallenge.clearProperty(anyString())).thenReturn(Mono.empty());
        // A raw bff_ token sent as a Bearer would be handed to the resource-server jwt decoder;
        // a real decoder REJECTS a non-JWT with a BadJwtException -> the resource server maps it
        // to a 401 (the prod behaviour), NOT a 500. Mirror that here so a stray bff_ Bearer on a
        // permitAll path (sessionOut) fails auth cleanly and still reaches the permitAll controller.
        when(jwtDecoder.decode(anyString()))
                .thenReturn(Mono.error(new org.springframework.security.oauth2.jwt.BadJwtException("not a jwt")));
    }

    private String registerAndGetToken(String email) {
        store.inviteEmail(email, "default").block();
        return new String(web.post().uri("/bff/register/google").contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"email\":\"" + email + "\"}")
                .exchange().expectStatus().isOk()
                .expectBody().returnResult().getResponseBody());
    }

    @Test
    void cookieDark_tokenStillInBody_noSetCookie() {
        store.inviteEmail("dark@x.com", "default").block();
        web.post().uri("/bff/register/google").contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"email\":\"dark@x.com\"}")
                .exchange().expectStatus().isOk()
                .expectHeader().doesNotExist(HttpHeaders.SET_COOKIE)
                .expectBody().jsonPath("$.token").exists();
    }

    @Test
    void legacyBearerHeader_resolvesMe() {
        registerAndGetToken("bearer@x.com");
        // /bff/me is `authenticated` at the chain (in prod the gateway forwards a Casdoor JWT).
        // The JWT email claim resolves the registered account (the prod resolution leg). The
        // dual-READ of the OPAQUE bff_ token (cookie OR Bearer header -> same row) is proven at
        // the store + bridge level (AccountStoreMfaSessionTest / SessionCookieWebFilterTest); the
        // bff_ token is NOT the chain credential on an authenticated endpoint.
        web.mutateWith(mockJwt().jwt(j -> j.claim("email", "bearer@x.com")))
                .get().uri("/bff/me")
                .exchange().expectStatus().isOk()
                .expectBody().jsonPath("$.id").isEqualTo("google:bearer@x.com");
    }

    @Test
    void getSession_shape() {
        registerAndGetToken("sess@x.com");
        web.mutateWith(mockJwt().jwt(j -> j.claim("email", "sess@x.com")))
                .get().uri("/bff/session")
                .exchange().expectStatus().isOk()
                .expectBody()
                .jsonPath("$.roles").isArray()
                .jsonPath("$.registrationComplete").isEqualTo(false)
                .jsonPath("$.mfaSatisfied").isEqualTo(false);   // default false -> fail closed
    }

    @Test
    void sessionOut_deletesRow_andRevokesSubject() {
        String token = extractToken(registerAndGetToken("out@x.com"));
        // sessionOut is permitAll (the opaque bff_ carrier is not chain-authenticated).
        web.post().uri("/bff/sessionOut").header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                .exchange().expectStatus().isOk()
                .expectBody().jsonPath("$.loggedOut").isEqualTo(true);
        // the row is gone -> the token no longer resolves a session.
        org.assertj.core.api.Assertions.assertThat(store.sessionOfToken(token).blockOptional())
                .isEmpty();
        // the subject's homeserver localparts were RevocationListed (best-effort).
        verify(revocations).revokeCoarse(eq("matrix"), anyString(), eq("logout"), anyLong());
        verify(revocations).revokeCoarse(eq("mastodon"), anyString(), eq("logout"), anyLong());
    }

    private static String extractToken(String json) {
        // tiny extractor — the body is {"token":"bff_...",...}
        int i = json.indexOf("\"token\":\"") + 9;
        int j = json.indexOf('"', i);
        return json.substring(i, j);
    }
}
