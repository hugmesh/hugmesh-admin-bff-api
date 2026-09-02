package net.hugmesh.adminbff;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webflux.test.autoconfigure.WebFluxTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
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
import net.hugmesh.adminbff.locallogin.LocalLoginRateLimiter;
import net.hugmesh.adminbff.provision.ServiceTokenBroker;
import net.hugmesh.adminbff.support.TestDatabaseConfig;
import net.hugmesh.adminbff.usage.UsageService;
import net.hugmesh.adminbff.web.ValidationExceptionHandler;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;

/**
 * Bean-validation contract on the public registration/login endpoints. A blank /
 * malformed email/username body is a clean 400 (mapped by ValidationExceptionHandler)
 * BEFORE the invite-gate lookup, so the durable store is never touched. A valid body
 * still flows through the existing invite/login logic (covered in AuthControllerTest).
 * These endpoints are permitAll, so no JWT is attached.
 */
@WebFluxTest(controllers = AuthController.class)
@Import({SecurityConfig.class, net.hugmesh.commons.security.DomainRegistry.class,
        net.hugmesh.adminbff.account.RegistrationDomainResolver.class, TestDatabaseConfig.class,
        ValidationExceptionHandler.class, LocalLoginRateLimiter.class})
class AuthControllerValidationTest {

    @Autowired WebTestClient web;

    @MockitoBean ServiceTokenBroker broker;
    @MockitoBean UsageService usage;
    @MockitoBean net.hugmesh.adminbff.suspension.SuspensionService suspensions;
    @MockitoBean net.hugmesh.adminbff.profile.ProfileForwarder profiles;
    @MockitoBean net.hugmesh.authcore.provision.GatewayRevocationClient revocations;
    @MockitoBean net.hugmesh.authcore.casdoor.MfaChallengeService mfaChallenge;
    @MockitoBean ReactiveJwtDecoder jwtDecoder;

    @TestConfiguration
    static class Cfg {
        @Bean AccountStore accountStore(DatabaseClient db) {
            AccountStore store = new AccountStore(net.hugmesh.adminbff.testutil.R2dbcRepos.of(db, net.hugmesh.authcore.account.AllowlistRepository.class), net.hugmesh.adminbff.testutil.R2dbcRepos.of(db, net.hugmesh.authcore.account.AccountRowRepository.class), net.hugmesh.adminbff.testutil.R2dbcRepos.of(db, net.hugmesh.authcore.account.BffSessionRepository.class), net.hugmesh.adminbff.testutil.R2dbcRepos.of(db, net.hugmesh.authcore.account.NamespaceGrantRepository.class), "admin@hugmesh.net");
            store.seedAdmins();
            return store;
        }

        /** A2 cookie service in its DARK default (cookie mode off). */
        @Bean net.hugmesh.authcore.config.SessionCookieService sessionCookieService() {
            return new net.hugmesh.authcore.config.SessionCookieService(false, true, null);
        }

        /** The account-takeover-by-collision guard, over the SAME real Testcontainers
         *  Postgres the durable {@code AccountStore} bean above uses. Never actually
         *  invoked by these tests (validation short-circuits before the controller body
         *  runs), but the bean must exist for the context to wire {@code AuthController}. */
        @Bean AccountLocalpartService accountLocalpartService(DatabaseClient db) {
            return new AccountLocalpartService(
                    net.hugmesh.adminbff.testutil.R2dbcRepos.of(db, AccountLocalpartRepository.class));
        }
    }

    @Test
    void registerGoogle_blankEmail_400() {
        web.post().uri("/bff/register/google").contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"email\":\"\"}")
                .exchange().expectStatus().isBadRequest()
                .expectBody()
                .jsonPath("$.error").isEqualTo("validation failed")
                .jsonPath("$.fields.email").exists();
    }

    @Test
    void registerGoogle_malformedEmail_400() {
        web.post().uri("/bff/register/google").contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"email\":\"nope\"}")
                .exchange().expectStatus().isBadRequest()
                .expectBody().jsonPath("$.fields.email").exists();
    }

    @Test
    void registerDiscord_missingUsername_400() {
        web.post().uri("/bff/register/discord").contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{}")
                .exchange().expectStatus().isBadRequest()
                .expectBody().jsonPath("$.fields.username").exists();
    }

    @Test
    void login_invalidProvider_400() {
        web.post().uri("/bff/login").contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"email\":\"a@b.com\",\"provider\":\"twitter\"}")
                .exchange().expectStatus().isBadRequest()
                .expectBody().jsonPath("$.fields.provider").exists();
    }

    @Test
    void registerGoogle_validButNotInvited_403_notValidationError() {
        when(usage.record(anyString(), org.mockito.ArgumentMatchers.any(), anyString())).thenReturn(Mono.empty());
        // A well-formed email passes validation and reaches the invite gate (403),
        // proving the validation layer does not shadow the existing business rule.
        web.post().uri("/bff/register/google").contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"email\":\"stranger@gmail.com\"}")
                .exchange().expectStatus().isForbidden()
                .expectBody().jsonPath("$.error").isEqualTo("email not invited by an admin");
    }
}
