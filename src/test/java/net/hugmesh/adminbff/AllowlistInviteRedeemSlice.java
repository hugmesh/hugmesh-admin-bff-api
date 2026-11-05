package net.hugmesh.adminbff;

import org.junit.jupiter.api.BeforeEach;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.webflux.test.autoconfigure.WebFluxTest;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.r2dbc.core.DatabaseClient;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.reactive.server.WebTestClient;
import reactor.core.publisher.Mono;
import net.hugmesh.adminbff.account.AccountCasdoorSubService;
import net.hugmesh.adminbff.account.AccountIssuerService;
import net.hugmesh.adminbff.account.AccountLocalpartRepository;
import net.hugmesh.adminbff.account.AccountLocalpartService;
import net.hugmesh.adminbff.account.RegistrationDomainResolver;
import net.hugmesh.adminbff.capability.DomainCapabilityService;
import net.hugmesh.adminbff.config.SecurityConfig;
import net.hugmesh.adminbff.domainlock.DomainLockService;
import net.hugmesh.adminbff.federation.FederationApiClient;
import net.hugmesh.adminbff.internalapi.InternalAccountController;
import net.hugmesh.adminbff.iso.IsoRepository;
import net.hugmesh.adminbff.locallogin.LocalLoginRateLimiter;
import net.hugmesh.adminbff.profile.ProfileForwarder;
import net.hugmesh.adminbff.provision.ServiceTokenBroker;
import net.hugmesh.adminbff.routeaccess.RouteAccessService;
import net.hugmesh.adminbff.suspension.SuspensionService;
import net.hugmesh.adminbff.support.TestDatabaseConfig;
import net.hugmesh.adminbff.testutil.R2dbcRepos;
import net.hugmesh.adminbff.urlregistry.UrlRegistryService;
import net.hugmesh.adminbff.usage.UsageService;
import net.hugmesh.authcore.account.AccountRowRepository;
import net.hugmesh.authcore.account.AccountStatus;
import net.hugmesh.authcore.account.AccountStore;
import net.hugmesh.authcore.account.AllowlistRepository;
import net.hugmesh.authcore.account.BffSessionRepository;
import net.hugmesh.authcore.account.NamespaceGrantRepository;
import net.hugmesh.authcore.casdoor.BffCustodyCipher;
import net.hugmesh.authcore.casdoor.MfaChallengeService;
import net.hugmesh.authcore.casdoor.MfaStepUpService;
import net.hugmesh.authcore.casdoor.OidcExchangeClient;
import net.hugmesh.authcore.config.SessionCookieService;
import net.hugmesh.authcore.provision.GatewayRevocationClient;
import net.hugmesh.authcore.username.FederationUsernameClient;
import net.hugmesh.authcore.username.UsernameGate;
import net.hugmesh.commons.security.DomainRegistry;

import java.util.List;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.mockAuthentication;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.springSecurity;

/**
 * Shared slice for hugmesh-admin-bff-api#111: an invite made from the admin console must be
 * redeemable by the register gate. The three concrete subclasses differ ONLY in the tenancy
 * shape ({@code app.tenancy.issuers} / the issuer-uri), so the same production wiring is
 * exercised on an unconfigured, a single-brand and a multi-brand install.
 *
 * <p>All three sides of the round trip are the REAL controllers over a REAL Postgres
 * ({@link TestDatabaseConfig}): the console ({@link AdminController},
 * {@code /bff/admin/allowlist}), user-bff's gate read ({@link InternalAccountController},
 * {@code GET /bff/internal/allowlist/**}, reachable here because the internal credential is
 * unarmed in tests) and admin-bff's own untokened register gate ({@link AuthController},
 * {@code POST /bff/register/**}). Nothing in the allowlist path is mocked.
 *
 * <p>The "domainless admin" is the principal a native {@code /bff/login} session carries:
 * auth-core's {@code BffCookieAuthenticationWebFilter} builds a
 * {@link UsernamePasswordAuthenticationToken} (account id, no credentials, role authorities),
 * not a Casdoor JWT, so {@code PrincipalDomain.of} resolves it to {@code NO_DOMAIN}. That is
 * the {@code e2e-admin} shape the issue measured on the compose lane.
 */
@WebFluxTest(controllers = {AdminController.class, InternalAccountController.class, AuthController.class})
@Import({SecurityConfig.class, DomainRegistry.class, RegistrationDomainResolver.class,
        TestDatabaseConfig.class, LocalLoginRateLimiter.class, AllowlistInviteRedeemSlice.Cfg.class})
abstract class AllowlistInviteRedeemSlice {

    @Autowired ApplicationContext context;
    @Autowired AccountStore store;
    @Autowired RegistrationDomainResolver registrationDomains;

    WebTestClient web;

    // AdminController collaborators (none of them on the allowlist path).
    @MockitoBean RouteAccessService routeAccess;
    @MockitoBean UrlRegistryService urlRegistry;
    @MockitoBean IsoRepository isoRepo;
    @MockitoBean UsageService usage;
    @MockitoBean SuspensionService suspensions;
    @MockitoBean DomainLockService domainLocks;
    @MockitoBean FederationApiClient federation;
    @MockitoBean GatewayRevocationClient revocations;
    @MockitoBean DomainCapabilityService domainCapabilities;
    @MockitoBean ReactiveJwtDecoder jwtDecoder;
    // InternalAccountController collaborators (none of them on the allowlist read).
    @MockitoBean MfaStepUpService mfaStepUp;
    @MockitoBean BffCustodyCipher custodyCipher;
    @MockitoBean OidcExchangeClient oidcExchange;
    @MockitoBean AccountCasdoorSubService casdoorSubs;
    @MockitoBean AccountIssuerService accountIssuers;
    // AuthController collaborators past the gate.
    @MockitoBean ServiceTokenBroker broker;
    @MockitoBean ProfileForwarder profiles;
    @MockitoBean MfaChallengeService mfaChallenge;

    @TestConfiguration
    static class Cfg {
        @Bean AccountStore accountStore(DatabaseClient db) {
            return new AccountStore(
                    R2dbcRepos.of(db, AllowlistRepository.class),
                    R2dbcRepos.of(db, AccountRowRepository.class),
                    R2dbcRepos.of(db, BffSessionRepository.class),
                    R2dbcRepos.of(db, NamespaceGrantRepository.class),
                    "admin@hugmesh.net");
        }

        @Bean SessionCookieService sessionCookieService() {
            return new SessionCookieService(false, true, null);
        }

        @Bean AccountLocalpartService accountLocalpartService(DatabaseClient db) {
            return new AccountLocalpartService(R2dbcRepos.of(db, AccountLocalpartRepository.class));
        }

        // Federation client disabled: only the local reserved-name fast path runs.
        @Bean FederationUsernameClient federationUsernameClient() {
            return new FederationUsernameClient(null, false, "X-Internal-Token", null);
        }

        @Bean UsernameGate usernameGate(FederationUsernameClient federationClient) {
            return new UsernameGate(federationClient);
        }
    }

    @BeforeEach
    void setUpSlice() {
        web = WebTestClient.bindToApplicationContext(context).apply(springSecurity()).build();
        when(usage.record(anyString(), any(), anyString())).thenReturn(Mono.empty());
        when(revocations.revokeSubject(anyString(), anyString(), anyLong())).thenReturn(Mono.empty());
        when(suspensions.statusFor(anyString())).thenReturn(Mono.just(AccountStatus.active()));
        when(profiles.forward(anyString(), any(), any())).thenReturn(Mono.empty());
    }

    /** A native-login admin: the non-JWT principal a {@code bff_} session carries. */
    WebTestClient asDomainlessAdmin() {
        return web.mutateWith(mockAuthentication(new UsernamePasswordAuthenticationToken(
                "local:e2e-admin", null,
                List.of(new SimpleGrantedAuthority("ROLE_USER"), new SimpleGrantedAuthority("ROLE_ADMIN")))));
    }

    WebTestClient.ResponseSpec invite(WebTestClient as, String body) {
        return as.post().uri("/bff/admin/allowlist").contentType(MediaType.APPLICATION_JSON)
                .bodyValue(body).exchange();
    }

    WebTestClient.ResponseSpec uninvite(WebTestClient as, String body) {
        return as.method(HttpMethod.DELETE).uri("/bff/admin/allowlist").contentType(MediaType.APPLICATION_JSON)
                .bodyValue(body).exchange();
    }

    /** user-bff's register-gate read: no {@code domain}, exactly as the issue measured it. */
    WebTestClient.ResponseSpec gateRead(String provider, String handle) {
        return web.get().uri("/bff/internal/allowlist/{p}/{h}", provider, handle).exchange();
    }

    /** admin-bff's own untokened register gate. */
    WebTestClient.ResponseSpec registerGoogle(String email) {
        return web.post().uri("/bff/register/google").contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"email\":\"" + email + "\"}").exchange();
    }

    WebTestClient.ResponseSpec registerDiscord(String handle) {
        return web.post().uri("/bff/register/discord").contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"username\":\"" + handle + "\"}").exchange();
    }

    /** The raw domain stamp(s) of an allowlist row, read straight from the table. */
    List<String> stampsOf(String provider, String handle) {
        return context.getBean(DatabaseClient.class)
                .sql("SELECT domain FROM allowlist WHERE provider = :p AND handle = :h")
                .bind("p", provider).bind("h", handle)
                .map(row -> row.get("domain", String.class))
                .all().collectList().block();
    }
}
