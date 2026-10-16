package net.hugmesh.adminbff.internalapi;

import net.hugmesh.adminbff.account.AccountCasdoorSubService;
import net.hugmesh.adminbff.account.AccountIssuerService;
import net.hugmesh.adminbff.account.AccountLocalpartService;
import net.hugmesh.adminbff.account.RegistrationDomainResolver;
import net.hugmesh.adminbff.config.SecurityConfig;
import net.hugmesh.adminbff.suspension.SuspensionService;
import net.hugmesh.adminbff.usage.UsageService;
import net.hugmesh.adminbff.web.ApiExceptionHandler;
import net.hugmesh.adminbff.web.ValidationExceptionHandler;
import net.hugmesh.authcore.account.Account;
import net.hugmesh.authcore.account.AccountStore;
import net.hugmesh.authcore.casdoor.MfaStepUpService;
import net.hugmesh.authcore.config.InternalTokenWebFilter;
import net.hugmesh.commons.security.DomainRegistry;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webflux.test.autoconfigure.WebFluxTest;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Import;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.reactive.server.WebTestClient;
import reactor.core.publisher.Mono;

import java.util.List;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.mockJwt;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.springSecurity;

/**
 * Wire-level contract of {@code POST /bff/internal/accounts/{id}/restart-onboarding}
 * (hugmesh-admin-bff-api#84) — the route hugmesh-user-bff-api#19 codes against. The unit tests in
 * {@link InternalAccountControllerTest} call the handler directly, so they cannot see the two
 * things this class pins: that the route is MAPPED at that exact verb + path (remove the
 * {@code @PostMapping} and every authorised call below is a 404), and that it sits behind the
 * {@code /bff/internal/**} authz gate — {@code ROLE_SERVICE} or the shared {@code X-Internal-Token}
 * ({@link InternalTokenWebFilter}), with the credential ARMED as in every production deployment.
 * Real {@link SecurityConfig}; every collaborator mocked; no database, no docker.
 */
@WebFluxTest(controllers = InternalAccountController.class)
@Import({SecurityConfig.class, DomainRegistry.class, ValidationExceptionHandler.class,
        ApiExceptionHandler.class, InternalTokenWebFilter.class})
@TestPropertySource(properties = {
        "app.internal.token=s3cret",
        "app.internal.token-header=X-Internal-Token"
})
class InternalAccountControllerRestartOnboardingWireTest {

    private static final String PATH = "/bff/internal/accounts/google:a@x.com/restart-onboarding";

    @Autowired ApplicationContext context;

    @MockitoBean ReactiveJwtDecoder jwtDecoder;
    @MockitoBean AccountStore accounts;
    @MockitoBean SuspensionService suspensions;
    @MockitoBean MfaStepUpService mfaStepUp;
    @MockitoBean AccountLocalpartService localparts;
    @MockitoBean AccountCasdoorSubService casdoorSubs;
    @MockitoBean AccountIssuerService accountIssuers;
    @MockitoBean RegistrationDomainResolver registrationDomains;
    @MockitoBean UsageService usage;

    WebTestClient client;

    private static Account acct(boolean complete) {
        return new Account("google:a@x.com", "google", "a@x.com", complete, List.of("user"));
    }

    @BeforeEach
    void setUp() {
        when(accounts.account("google:a@x.com")).thenReturn(Mono.just(acct(true)));
        when(accounts.account("missing")).thenReturn(Mono.empty());
        when(accounts.restartOnboarding(any())).thenReturn(Mono.just(acct(false)));
        when(localparts.localpartsOf("google:a@x.com")).thenReturn(Mono.just(
                new AccountLocalpartService.ResolvedLocalparts("alice", "alice_m")));
        client = WebTestClient.bindToApplicationContext(context).apply(springSecurity()).build();
    }

    @Test
    void serviceJwtPlusInternalToken_is200_withTheResetAccountAndItsPersistedLocalpart() {
        client.mutateWith(mockJwt().authorities(new SimpleGrantedAuthority("ROLE_SERVICE")))
                .post().uri(PATH).header("X-Internal-Token", "s3cret").exchange()
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$.id").isEqualTo("google:a@x.com")
                .jsonPath("$.registrationComplete").isEqualTo(false)
                .jsonPath("$.localpart").isEqualTo("alice")
                .jsonPath("$.mastodonLocalpart").isEqualTo("alice_m");
        verify(accounts).restartOnboarding(acct(true));
    }

    @Test
    void serviceJwtAlone_is401_onceTheInternalTokenIsArmed() {
        // With the shared credential armed (every production deployment) InternalTokenWebFilter
        // runs AFTER the security chain and demands the token even from a ROLE_SERVICE JWT. The
        // JWT-only leg of the route policy is pinned by InternalSurfaceRoleMatrixTest.
        client.mutateWith(mockJwt().authorities(new SimpleGrantedAuthority("ROLE_SERVICE")))
                .post().uri(PATH).exchange().expectStatus().isUnauthorized();
        verify(accounts, never()).restartOnboarding(any());
    }

    @Test
    void validInternalToken_is200_andResetsTheAccount() {
        client.post().uri(PATH).header("X-Internal-Token", "s3cret").exchange()
                .expectStatus().isOk()
                .expectBody().jsonPath("$.registrationComplete").isEqualTo(false);
        verify(accounts).restartOnboarding(acct(true));
    }

    @Test
    void unknownAccount_is404_underAValidInternalToken() {
        client.post().uri("/bff/internal/accounts/missing/restart-onboarding")
                .header("X-Internal-Token", "s3cret").exchange()
                .expectStatus().isNotFound();
        verify(accounts, never()).restartOnboarding(any());
    }

    @Test
    void anonymous_is401_andNothingIsReset() {
        client.post().uri(PATH).exchange().expectStatus().isUnauthorized();
        verify(accounts, never()).restartOnboarding(any());
    }

    @Test
    void wrongInternalToken_is401_andNothingIsReset() {
        client.post().uri(PATH).header("X-Internal-Token", "WRONG").exchange()
                .expectStatus().isUnauthorized();
        verify(accounts, never()).restartOnboarding(any());
    }

    @Test
    void everyHumanRole_is403_andNothingIsReset() {
        // A human super-role must never be able to reset ANOTHER account's onboarding: the role
        // hierarchy has no edge to SERVICE.
        client.mutateWith(mockJwt().authorities(
                        new SimpleGrantedAuthority("ROLE_USER"),
                        new SimpleGrantedAuthority("ROLE_ADMIN"),
                        new SimpleGrantedAuthority("ROLE_SUPERADMIN")))
                .post().uri(PATH).exchange().expectStatus().isForbidden();
        verify(accounts, never()).restartOnboarding(any());
    }

    @Test
    void getIsNotAllowed_theVerbIsPostOnly() {
        client.mutateWith(mockJwt().authorities(new SimpleGrantedAuthority("ROLE_SERVICE")))
                .get().uri(PATH).header("X-Internal-Token", "s3cret").exchange()
                .expectStatus().isEqualTo(405);
        verify(accounts, never()).restartOnboarding(any());
    }
}
