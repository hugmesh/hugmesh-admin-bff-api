package net.hugmesh.adminbff.mfa;

import net.hugmesh.adminbff.config.SecurityConfig;
import net.hugmesh.adminbff.web.ApiExceptionHandler;
import net.hugmesh.adminbff.web.ValidationExceptionHandler;
import net.hugmesh.authcore.account.Account;
import net.hugmesh.authcore.account.AccountStore;
import net.hugmesh.authcore.account.BffSession;
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
import java.util.Set;

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

    /** A live session row for {@code account} carrying an MFA stamp made at {@code at} with {@code amr}. */
    static BffSession stamped(String token, Account account, LocalDateTime at, String amr) {
        return new BffSession(token, account.id(), LocalDateTime.now().minusHours(1),
                LocalDateTime.now().plusHours(1), true, at, amr, false);
    }

    /** A live session row for {@code account} that was never stamped. */
    static BffSession unstamped(String token, Account account) {
        return new BffSession(token, account.id(), LocalDateTime.now().minusHours(1),
                LocalDateTime.now().plusHours(1), false, null, null, false);
    }

    /** A merged requirement: required, with the given grace (0 = platform window) and methods. */
    static MfaRequirement requirement(long graceSeconds, String... methods) {
        return new MfaRequirement(true, graceSeconds, graceSeconds == 0, methods.length > 0, Set.of(methods));
    }

    @BeforeEach
    void setUp() {
        web = WebTestClient.bindToApplicationContext(context).build();
        when(policies.requirementFor(anyString(), any())).thenReturn(Mono.just(MfaRequirement.UNKNOWN));
        when(accounts.sessionOfToken(anyString())).thenReturn(Mono.empty());
        // The cookie auth filter (auth-core) reads mfaStateOf to grant the no-window MFA_SATISFIED
        // authority on a bff_ principal; the filter under test ignores that authority and reads
        // the row itself, so the two are stubbed independently.
        when(accounts.mfaStateOf(anyString())).thenReturn(Mono.empty());
        when(accounts.sessionRow(anyString())).thenReturn(Mono.empty());
        when(accounts.sessionOfToken("bff_A")).thenReturn(Mono.just(ADMIN_A));
        when(accounts.sessionRow("bff_A")).thenReturn(Mono.just(unstamped("bff_A", ADMIN_A)));
        when(accounts.sessionOfToken("bff_B")).thenReturn(Mono.just(USER_B));
        when(accounts.sessionRow("bff_B")).thenReturn(Mono.just(stamped("bff_B", USER_B, LocalDateTime.now(), "otp")));
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
        when(accounts.sessionRow("bff_C")).thenReturn(Mono.just(stamped("bff_C", ADMIN_C, LocalDateTime.now(), "otp")));

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
        // The principal lookup still answers A; the evidence row now names B's account.
        when(accounts.sessionRow("bff_A")).thenReturn(Mono.just(stamped("bff_A", USER_B, LocalDateTime.now(), "otp")));

        denied(web.get().uri(PROBE).header(HttpHeaders.AUTHORIZATION, "Bearer bff_A"));
    }

    @Test
    void aStampOlderThanTheFreshnessWindow_isDenied() {
        when(accounts.sessionRow("bff_A"))
                .thenReturn(Mono.just(stamped("bff_A", ADMIN_A, LocalDateTime.now().minusMinutes(11), "otp")));

        denied(web.get().uri(PROBE).header(HttpHeaders.AUTHORIZATION, "Bearer bff_A"));
    }

    @Test
    void anMfaLookupThatYieldsNothing_failsClosed() {
        when(accounts.sessionRow("bff_A")).thenReturn(Mono.empty());

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
        when(accounts.sessionRow("bff_A")).thenReturn(Mono.just(stamped("bff_A", ADMIN_A, LocalDateTime.now(), "otp")));

        web.get().uri(PROBE).cookie(SessionCookieWebFilter.SESSION_COOKIE, "bff_A").exchange()
                .expectStatus().isOk()
                .expectBody(String.class).isEqualTo("REACHED acct-a");
    }

    @Test
    void bearerOnly_freshlyStampedAdmin_isLetThrough_asThatAdmin() {
        when(accounts.sessionRow("bff_A")).thenReturn(Mono.just(stamped("bff_A", ADMIN_A, LocalDateTime.now(), "otp")));

        web.get().uri(PROBE).header(HttpHeaders.AUTHORIZATION, "Bearer bff_A").exchange()
                .expectStatus().isOk()
                .expectBody(String.class).isEqualTo("REACHED acct-a");
    }

    @Test
    void freshlyStampedBearer_isNotSpoiledByAStaleCookieOfAnotherSession() {
        when(accounts.sessionRow("bff_A")).thenReturn(Mono.just(stamped("bff_A", ADMIN_A, LocalDateTime.now(), "otp")));
        when(accounts.sessionRow("bff_B")).thenReturn(Mono.just(unstamped("bff_B", USER_B)));

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

        verify(accounts, never()).sessionRow("bff_B");
    }

    // ── graceSeconds: the strictest applicable window, 0 = the platform window ─────────

    @Test
    void grace_aStampYoungerThanTheGrace_isLetThrough() {
        when(policies.requirementFor(anyString(), any())).thenReturn(Mono.just(requirement(120)));
        when(accounts.sessionRow("bff_A"))
                .thenReturn(Mono.just(stamped("bff_A", ADMIN_A, LocalDateTime.now().minusSeconds(30), "otp")));

        web.get().uri(PROBE).header(HttpHeaders.AUTHORIZATION, "Bearer bff_A").exchange()
                .expectStatus().isOk()
                .expectBody(String.class).isEqualTo("REACHED acct-a");
    }

    /** Within the platform's 10m window, so only the per-role grace can be what denies it. */
    @Test
    void grace_aStampOlderThanTheGrace_butInsideThePlatformWindow_isDenied() {
        when(policies.requirementFor(anyString(), any())).thenReturn(Mono.just(requirement(120)));
        when(accounts.sessionRow("bff_A"))
                .thenReturn(Mono.just(stamped("bff_A", ADMIN_A, LocalDateTime.now().minusSeconds(121), "otp")));

        denied(web.get().uri(PROBE).header(HttpHeaders.AUTHORIZATION, "Bearer bff_A"));
    }

    @Test
    void grace_noStampAtAll_isDenied() {
        when(policies.requirementFor(anyString(), any())).thenReturn(Mono.just(requirement(3600)));

        denied(web.get().uri(PROBE).header(HttpHeaders.AUTHORIZATION, "Bearer bff_A"));
    }

    @Test
    void grace_aSetFlagWithNoTimestamp_cannotProveFreshness_andIsDenied() {
        when(policies.requirementFor(anyString(), any())).thenReturn(Mono.just(requirement(3600)));
        when(accounts.sessionRow("bff_A")).thenReturn(Mono.just(stamped("bff_A", ADMIN_A, null, "otp")));

        denied(web.get().uri(PROBE).header(HttpHeaders.AUTHORIZATION, "Bearer bff_A"));
    }

    /** grace 0 is the platform window (10m here), not "younger than nothing": the retry after a challenge passes. */
    @Test
    void grace_zero_isThePlatformWindow_soAFreshStampPasses_andAnElevenMinuteOneDoesNot() {
        when(policies.requirementFor(anyString(), any())).thenReturn(Mono.just(requirement(0)));
        when(accounts.sessionRow("bff_A"))
                .thenReturn(Mono.just(stamped("bff_A", ADMIN_A, LocalDateTime.now().minusMinutes(9), "otp")));
        web.get().uri(PROBE).header(HttpHeaders.AUTHORIZATION, "Bearer bff_A").exchange().expectStatus().isOk();

        when(accounts.sessionRow("bff_A"))
                .thenReturn(Mono.just(stamped("bff_A", ADMIN_A, LocalDateTime.now().minusMinutes(11), "otp")));
        denied(web.get().uri(PROBE).header(HttpHeaders.AUTHORIZATION, "Bearer bff_A"));
    }

    /** A grace longer than the platform window extends it only when no sibling role is on the platform window. */
    @Test
    void grace_longerThanThePlatformWindow_isHonoured_whenItIsTheOnlyParticipant() {
        when(policies.requirementFor(anyString(), any())).thenReturn(Mono.just(requirement(3600)));
        when(accounts.sessionRow("bff_A"))
                .thenReturn(Mono.just(stamped("bff_A", ADMIN_A, LocalDateTime.now().minusMinutes(30), "otp")));

        web.get().uri(PROBE).header(HttpHeaders.AUTHORIZATION, "Bearer bff_A").exchange().expectStatus().isOk();
    }

    @Test
    void grace_longerThanThePlatformWindow_isCapped_whenASiblingIsOnThePlatformWindow() {
        when(policies.requirementFor(anyString(), any()))
                .thenReturn(Mono.just(new MfaRequirement(true, 3600, true, false, Set.of())));
        when(accounts.sessionRow("bff_A"))
                .thenReturn(Mono.just(stamped("bff_A", ADMIN_A, LocalDateTime.now().minusMinutes(30), "otp")));

        denied(web.get().uri(PROBE).header(HttpHeaders.AUTHORIZATION, "Bearer bff_A"));
    }

    // ── methods: the stamped factor must be one the policy allows ──────────────────────

    @Test
    void methods_aStampMadeWithAnAllowedFactor_isLetThrough() {
        when(policies.requirementFor(anyString(), any())).thenReturn(Mono.just(requirement(0, "webauthn", "otp")));
        when(accounts.sessionRow("bff_A"))
                .thenReturn(Mono.just(stamped("bff_A", ADMIN_A, LocalDateTime.now(), "otp")));

        web.get().uri(PROBE).header(HttpHeaders.AUTHORIZATION, "Bearer bff_A").exchange()
                .expectStatus().isOk()
                .expectBody(String.class).isEqualTo("REACHED acct-a");
    }

    @Test
    void methods_aFreshStampMadeWithADisallowedFactor_isDenied() {
        when(policies.requirementFor(anyString(), any())).thenReturn(Mono.just(requirement(0, "webauthn")));
        when(accounts.sessionRow("bff_A"))
                .thenReturn(Mono.just(stamped("bff_A", ADMIN_A, LocalDateTime.now(), "recovery")));

        denied(web.get().uri(PROBE).header(HttpHeaders.AUTHORIZATION, "Bearer bff_A"));
    }

    /** The stamp writes "" when the factor is unknown; a constrained policy cannot accept that. */
    @Test
    void methods_aFreshStampThatRecordedNoMethod_failsClosed_whenMethodsAreConstrained() {
        when(policies.requirementFor(anyString(), any())).thenReturn(Mono.just(requirement(0, "webauthn", "otp")));
        when(accounts.sessionRow("bff_A")).thenReturn(Mono.just(stamped("bff_A", ADMIN_A, LocalDateTime.now(), "")));
        denied(web.get().uri(PROBE).header(HttpHeaders.AUTHORIZATION, "Bearer bff_A"));

        when(accounts.sessionRow("bff_A")).thenReturn(Mono.just(stamped("bff_A", ADMIN_A, LocalDateTime.now(), null)));
        denied(web.get().uri(PROBE).header(HttpHeaders.AUTHORIZATION, "Bearer bff_A"));
    }

    @Test
    void methods_unconstrained_acceptsAFreshStampThatRecordedNoMethod() {
        when(policies.requirementFor(anyString(), any())).thenReturn(Mono.just(requirement(0)));
        when(accounts.sessionRow("bff_A")).thenReturn(Mono.just(stamped("bff_A", ADMIN_A, LocalDateTime.now(), "")));

        web.get().uri(PROBE).header(HttpHeaders.AUTHORIZATION, "Bearer bff_A").exchange().expectStatus().isOk();
    }

    @Test
    void methods_anUnsatisfiableIntersection_deniesEveryFactor() {
        when(policies.requirementFor(anyString(), any()))
                .thenReturn(Mono.just(new MfaRequirement(true, 0, true, true, Set.of())));
        for (String amr : List.of("webauthn", "otp", "recovery")) {
            when(accounts.sessionRow("bff_A")).thenReturn(Mono.just(stamped("bff_A", ADMIN_A, LocalDateTime.now(), amr)));
            denied(web.get().uri(PROBE).header(HttpHeaders.AUTHORIZATION, "Bearer bff_A"));
        }
    }

    @Test
    void methods_andGrace_areBothChecked_onTheSameRow() {
        when(policies.requirementFor(anyString(), any())).thenReturn(Mono.just(requirement(120, "otp")));
        // right method, too old
        when(accounts.sessionRow("bff_A"))
                .thenReturn(Mono.just(stamped("bff_A", ADMIN_A, LocalDateTime.now().minusSeconds(200), "otp")));
        denied(web.get().uri(PROBE).header(HttpHeaders.AUTHORIZATION, "Bearer bff_A"));
        // fresh, wrong method
        when(accounts.sessionRow("bff_A"))
                .thenReturn(Mono.just(stamped("bff_A", ADMIN_A, LocalDateTime.now(), "webauthn")));
        denied(web.get().uri(PROBE).header(HttpHeaders.AUTHORIZATION, "Bearer bff_A"));
        // fresh and allowed
        when(accounts.sessionRow("bff_A"))
                .thenReturn(Mono.just(stamped("bff_A", ADMIN_A, LocalDateTime.now(), "otp")));
        web.get().uri(PROBE).header(HttpHeaders.AUTHORIZATION, "Bearer bff_A").exchange().expectStatus().isOk();
    }

    @Test
    void anExpiredSession_hasNoEvidence_whateverItsStampSays() {
        when(policies.requirementFor(anyString(), any())).thenReturn(Mono.just(requirement(3600)));
        // sessionRow resolves EMPTY for an expired row (the store reaps it); the stamp is unreachable.
        when(accounts.sessionRow("bff_A")).thenReturn(Mono.empty());

        denied(web.get().uri(PROBE).header(HttpHeaders.AUTHORIZATION, "Bearer bff_A"));
    }
}
