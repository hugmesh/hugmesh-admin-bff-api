package net.hugmesh.adminbff.mfa;

import net.hugmesh.adminbff.config.SecurityConfig;
import net.hugmesh.adminbff.web.ApiExceptionHandler;
import net.hugmesh.adminbff.web.ValidationExceptionHandler;
import net.hugmesh.authcore.account.Account;
import net.hugmesh.authcore.account.AccountStore;
import net.hugmesh.authcore.casdoor.MfaStepUpService;
import net.hugmesh.authcore.config.BffCookieAuthenticationWebFilter;
import net.hugmesh.authcore.config.SessionCookieWebFilter;
import net.hugmesh.commons.security.DomainRegistry;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.webflux.test.autoconfigure.WebFluxTest;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.http.HttpHeaders;
import org.springframework.security.core.Authentication;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;

import java.time.Duration;
import java.time.LocalDateTime;
import java.util.List;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * The MFA evidence {@link RoleMfaPolicyEnforcementFilter} accepts must belong to the SAME
 * session the principal was built from.
 *
 * <p>Runs the real carrier chain: {@link SessionCookieWebFilter} (keeps an explicit
 * {@code Bearer bff_...} over the cookie, else bridges the cookie into that header),
 * {@link BffCookieAuthenticationWebFilter} (builds the principal from that header), the
 * production {@link SecurityConfig}, the filter under test and a real {@link MfaStepUpService}.
 * Only the account store and the policy answer are mocks.
 *
 * <p>Session {@code bff_A} is an ADMIN with no MFA stamp; {@code bff_B} is a plain USER with a
 * fresh stamp. Before the fix, {@code Authorization: Bearer bff_A} plus
 * {@code Cookie: bff_session=bff_B} reached the admin handler as A, on B's stamp.
 */
@WebFluxTest(controllers = RoleMfaPolicyEnforcementEvidenceBindingTest.Probe.class,
        properties = {RoleMfaPolicyEnforcementFilter.FLAG + "=true"})
@Import({SecurityConfig.class, ValidationExceptionHandler.class, ApiExceptionHandler.class,
        SessionCookieWebFilter.class, BffCookieAuthenticationWebFilter.class,
        RoleMfaPolicyEnforcementFilter.class, RoleMfaPolicyEnforcementEvidenceBindingTest.Wiring.class,
        RoleMfaPolicyEnforcementEvidenceBindingTest.Probe.class})
class RoleMfaPolicyEnforcementEvidenceBindingTest {

    static final String PROBE = "/bff/admin/probe/x";

    static final Account ADMIN_A = new Account("acct-a", "casdoor", "alice", true, List.of("admin"));
    static final Account USER_B = new Account("acct-b", "casdoor", "bob", true, List.of("user"));
    static final Account ADMIN_C = new Account("acct-c", "casdoor", "carol", true, List.of("admin"));

    /** A privileged handler that names the principal it ran as. */
    @RestController
    static class Probe {
        @GetMapping("/bff/admin/probe/{id}")
        Mono<String> probe(@PathVariable String id, Authentication auth) {
            return Mono.just("REACHED " + auth.getName());
        }
    }

    @TestConfiguration
    static class Wiring {
        @Bean
        DomainRegistry domainRegistry() {
            return new DomainRegistry("", "");
        }

        @Bean
        MfaStepUpService mfaStepUpService(AccountStore store) {
            return new MfaStepUpService(store, true, Duration.ofMinutes(10));
        }
    }

    @Autowired ApplicationContext context;

    @MockitoBean AccountStore accounts;
    @MockitoBean RoleMfaPolicyService policies;
    @MockitoBean org.springframework.security.oauth2.jwt.ReactiveJwtDecoder jwtDecoder;

    WebTestClient web;

    static AccountStore.MfaState fresh() {
        return new AccountStore.MfaState(true, LocalDateTime.now());
    }

    static AccountStore.MfaState none() {
        return new AccountStore.MfaState(false, null);
    }

    @BeforeEach
    void setUp() {
        web = WebTestClient.bindToApplicationContext(context).build();
        when(policies.requiredForAny(anyString(), any())).thenReturn(Mono.just(true));
        when(accounts.sessionOfToken(anyString())).thenReturn(Mono.empty());
        when(accounts.mfaStateOf(anyString())).thenReturn(Mono.empty());
        when(accounts.sessionOfToken("bff_A")).thenReturn(Mono.just(ADMIN_A));
        when(accounts.mfaStateOf("bff_A")).thenReturn(Mono.just(none()));
        when(accounts.sessionOfToken("bff_B")).thenReturn(Mono.just(USER_B));
        when(accounts.mfaStateOf("bff_B")).thenReturn(Mono.just(fresh()));
    }

    private void denied(WebTestClient.RequestHeadersSpec<?> request) {
        request.exchange()
                .expectStatus().isForbidden()
                .expectHeader().valueEquals(RoleMfaPolicyEnforcementFilter.SIGNAL_HEADER, "true");
    }

    // ── the exploit and its spellings ────────────────────────────────────────────────

    @Test
    void bearerOfAnUnstampedAdmin_plusAnotherAccountsFreshCookie_isDenied() {
        denied(web.get().uri(PROBE)
                .header(HttpHeaders.AUTHORIZATION, "Bearer bff_A")
                .cookie(SessionCookieWebFilter.SESSION_COOKIE, "bff_B"));
    }

    /** Refused, never served: whichever carrier wins, no handler runs on the other's stamp. */
    private void refused(WebTestClient.RequestHeadersSpec<?> request) {
        request.exchange()
                .expectStatus().isForbidden()
                .expectBody(String.class).value(body ->
                        org.assertj.core.api.Assertions.assertThat(String.valueOf(body)).doesNotContain("REACHED"));
    }

    /**
     * Spellings the cookie bridge does not recognise as an explicit {@code bff_} Bearer: the
     * bridge then replaces the header with the cookie, so the principal is B (a plain user) and
     * the role check refuses. Either way A never runs on B's stamp.
     */
    @Test
    void lowerCaseBearerScheme_plusAnotherAccountsFreshCookie_isDenied() {
        refused(web.get().uri(PROBE)
                .header(HttpHeaders.AUTHORIZATION, "bearer bff_A")
                .cookie(SessionCookieWebFilter.SESSION_COOKIE, "bff_B"));
    }

    @Test
    void paddedBearer_plusAnotherAccountsFreshCookie_isDenied() {
        refused(web.get().uri(PROBE)
                .header(HttpHeaders.AUTHORIZATION, "  Bearer   bff_A  ")
                .cookie(SessionCookieWebFilter.SESSION_COOKIE, "bff_B"));
    }

    @Test
    void twoSessionCookies_withTheFreshOneSecond_doNotLendTheStamp() {
        denied(web.get().uri(PROBE)
                .header(HttpHeaders.AUTHORIZATION, "Bearer bff_A")
                .cookie(SessionCookieWebFilter.SESSION_COOKIE, "bff_A")
                .cookie(SessionCookieWebFilter.SESSION_COOKIE, "bff_B"));
    }

    @Test
    void twoAuthorizationHeaders_withTheFreshSessionSecond_doNotLendTheStamp() {
        denied(web.get().uri(PROBE)
                .header(HttpHeaders.AUTHORIZATION, "Bearer bff_A", "Bearer bff_B"));
    }

    @Test
    void anotherFreshAdminsCookie_isNotEvidenceForThisAdmin() {
        when(accounts.sessionOfToken("bff_C")).thenReturn(Mono.just(ADMIN_C));
        when(accounts.mfaStateOf("bff_C")).thenReturn(Mono.just(fresh()));

        denied(web.get().uri(PROBE)
                .header(HttpHeaders.AUTHORIZATION, "Bearer bff_A")
                .cookie(SessionCookieWebFilter.SESSION_COOKIE, "bff_C"));
    }

    @Test
    void theEncodedPathSpelling_withTheBorrowedCookie_isDeniedToo() {
        denied(web.get().uri(java.net.URI.create("/bff/%61dmin/probe/x"))
                .header(HttpHeaders.AUTHORIZATION, "Bearer bff_A")
                .cookie(SessionCookieWebFilter.SESSION_COOKIE, "bff_B"));
    }

    /**
     * The second binding on its own: the evidence session must name the principal's account.
     * The store answers A for the principal lookup and then B for the evidence lookup (a session
     * row re-bound between the two reads); the stamp must not count.
     */
    @Test
    void evidenceSessionThatNoLongerNamesThePrincipalsAccount_isDenied() {
        when(accounts.sessionOfToken("bff_A")).thenReturn(Mono.just(ADMIN_A), Mono.just(USER_B));
        when(accounts.mfaStateOf("bff_A")).thenReturn(Mono.just(none()), Mono.just(fresh()));

        denied(web.get().uri(PROBE).header(HttpHeaders.AUTHORIZATION, "Bearer bff_A"));
    }

    @Test
    void aStampOlderThanTheFreshnessWindow_isDenied() {
        when(accounts.mfaStateOf("bff_A"))
                .thenReturn(Mono.just(new AccountStore.MfaState(true, LocalDateTime.now().minusMinutes(11))));

        denied(web.get().uri(PROBE).header(HttpHeaders.AUTHORIZATION, "Bearer bff_A"));
    }

    @Test
    void anMfaLookupThatYieldsNothing_failsClosed() {
        when(accounts.mfaStateOf("bff_A")).thenReturn(Mono.empty());

        denied(web.get().uri(PROBE).header(HttpHeaders.AUTHORIZATION, "Bearer bff_A"));
    }

    // ── controls: the legitimate carriers still work ────────────────────────────────────

    @Test
    void bearerOnly_unstampedAdmin_isDenied() {
        denied(web.get().uri(PROBE).header(HttpHeaders.AUTHORIZATION, "Bearer bff_A"));
    }

    @Test
    void cookieOnly_unstampedAdmin_isDenied() {
        denied(web.get().uri(PROBE).cookie(SessionCookieWebFilter.SESSION_COOKIE, "bff_A"));
    }

    @Test
    void cookieOnly_freshlyStampedAdmin_isLetThrough_asThatAdmin() {
        when(accounts.mfaStateOf("bff_A")).thenReturn(Mono.just(fresh()));

        web.get().uri(PROBE).cookie(SessionCookieWebFilter.SESSION_COOKIE, "bff_A").exchange()
                .expectStatus().isOk()
                .expectBody(String.class).isEqualTo("REACHED acct-a");
    }

    @Test
    void bearerOnly_freshlyStampedAdmin_isLetThrough_asThatAdmin() {
        when(accounts.mfaStateOf("bff_A")).thenReturn(Mono.just(fresh()));

        web.get().uri(PROBE).header(HttpHeaders.AUTHORIZATION, "Bearer bff_A").exchange()
                .expectStatus().isOk()
                .expectBody(String.class).isEqualTo("REACHED acct-a");
    }

    @Test
    void freshlyStampedBearer_isNotSpoiledByAStaleCookieOfAnotherSession() {
        when(accounts.mfaStateOf("bff_A")).thenReturn(Mono.just(fresh()));
        when(accounts.mfaStateOf("bff_B")).thenReturn(Mono.just(none()));

        web.get().uri(PROBE)
                .header(HttpHeaders.AUTHORIZATION, "Bearer bff_A")
                .cookie(SessionCookieWebFilter.SESSION_COOKIE, "bff_B").exchange()
                .expectStatus().isOk()
                .expectBody(String.class).isEqualTo("REACHED acct-a");
    }

    @Test
    void theEvidenceLookupNeverReadsTheBorrowedCookie() {
        web.get().uri(PROBE)
                .header(HttpHeaders.AUTHORIZATION, "Bearer bff_A")
                .cookie(SessionCookieWebFilter.SESSION_COOKIE, "bff_B").exchange();

        verify(accounts, never()).mfaStateOf("bff_B");
    }
}
