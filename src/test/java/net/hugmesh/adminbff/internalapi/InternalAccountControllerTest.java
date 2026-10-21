package net.hugmesh.adminbff.internalapi;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.web.server.ResponseStatusException;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;
import net.hugmesh.adminbff.account.AccountCasdoorSubService;
import net.hugmesh.adminbff.account.AccountIssuerService;
import net.hugmesh.adminbff.account.AccountLocalpartService;
import net.hugmesh.adminbff.account.RegistrationDomainResolver;
import net.hugmesh.adminbff.suspension.SuspensionService;
import net.hugmesh.adminbff.usage.UsageService;
import net.hugmesh.authcore.account.Account;
import net.hugmesh.authcore.account.AccountStatus;
import net.hugmesh.authcore.account.AccountStore;
import net.hugmesh.authcore.account.BffSession;
import net.hugmesh.authcore.account.BffSessionRow;
import net.hugmesh.authcore.casdoor.BffCustodyCipher;
import net.hugmesh.authcore.casdoor.MfaStepUpService;
import net.hugmesh.authcore.casdoor.OidcExchangeClient;
import net.hugmesh.authcore.casdoor.OidcTokens;

import org.mockito.ArgumentCaptor;

import java.time.LocalDateTime;
import java.util.Base64;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit coverage for the {@code /bff/internal} account/session API: each endpoint delegates to
 * {@link AccountStore} and maps absent accounts to 404 / unknown providers to 400, plus the
 * band-180 BFF-JWT-custody tail ({@code /custody/stamp} + {@code /session/exchange}) exercised
 * with a REAL {@link BffCustodyCipher} (deterministic test key, so encrypt/decrypt round-trips)
 * + a mocked {@link AccountStore} + a mocked {@link OidcExchangeClient}.
 */
class InternalAccountControllerTest {

    private final AccountStore accounts = mock(AccountStore.class);
    private final SuspensionService suspensions = mock(SuspensionService.class);
    private final AccountLocalpartService localparts = mock(AccountLocalpartService.class);
    private final AccountCasdoorSubService casdoorSubs = mock(AccountCasdoorSubService.class);
    /** Changeset 301 — the brand/issuer stamp+read. Mocked here (its OWN trusted-issuer
     *  validation is unit-tested in {@code AccountIssuerServiceTest}); these tests assert only
     *  that the controller decodes the raw iss, hands it to stamp(), and surfaces the
     *  service's answer on introspect. */
    private final AccountIssuerService accountIssuers = mock(AccountIssuerService.class);

    /** Real cipher with a deterministic 32-byte base64 key → encrypt/decrypt round-trips. */
    private static final BffCustodyCipher CIPHER = new BffCustodyCipher(
            Base64.getEncoder().encodeToString("0123456789abcdef0123456789abcdef".getBytes()));

    /** An INERT cipher (no key) → isAvailable()==false, decrypt()→null (the dark/default posture). */
    private static final BffCustodyCipher INERT_CIPHER = new BffCustodyCipher("");

    private final OidcExchangeClient oidc = mock(OidcExchangeClient.class);

    /** Real step-up service (ARMED, 10m window) backing introspect's WINDOWED mfaSatisfied. */
    private final MfaStepUpService mfaStepUp =
            new MfaStepUpService(accounts, true, java.time.Duration.ofMinutes(10));

    /** Untenanted resolver (no {@code app.tenancy.issuers}, no pin) — its {@code fallback()}
     *  is {@link AccountStore#DEFAULT_DOMAIN}, the domain a single-tenant install's seed and
     *  the changeset-220 back-fill stamp. So the invite-gate assertions below read the SAME
     *  rows as before the auth-core issue #1 fix, now through the domain-scoped overload. */
    private final RegistrationDomainResolver registrationDomains =
            new RegistrationDomainResolver(new net.hugmesh.commons.security.DomainRegistry("", ""), "");

    /** Decision 55 (hugmesh-admin-bff-api#85) — {@code POST /bff/internal/usage}'s sole
     *  collaborator; a straight pass-through, so these tests assert the exact arguments
     *  forwarded rather than any persistence side effect (that is {@code UsageServiceTest}'s
     *  job). */
    private final UsageService usage = mock(UsageService.class);

    /** The account/session API surface (custody seams null — those endpoints aren't under test here). */
    private final InternalAccountController controller =
            new InternalAccountController(accounts, suspensions, mfaStepUp, CIPHER, oidc, 60L,
                    localparts, casdoorSubs, accountIssuers, registrationDomains, usage);

    @BeforeEach
    void setUp() {
        // The /session/exchange suspension-gate resolves the account via sessionOfToken before
        // serving custody. Default to "no account resolvable" so the gate is a NO-OP for the
        // tests that drive the custody path through sessionRow; the suspension tests override
        // this with a concrete account + a banned/suspended status.
        when(accounts.sessionOfToken(any())).thenReturn(Mono.empty());
        // Default: no collision, resolves to a stub localpart — the ensureAccount tests below
        // assert on the account id/roles, not the exact localpart value.
        when(localparts.resolveAndPersist(any(), any())).thenReturn(Mono.just("a"));
        // Default for the plain-read path (account()/complete()): unset — Mockito's default
        // unstubbed answer for a Mono-returning method is null, NOT Mono.empty(), so every test
        // that reaches readWithLocalpart (anything calling account()/complete()) needs this or
        // it NPEs even though it never asserts on localpart.
        when(localparts.localpartOf(any())).thenReturn(Mono.empty());
        // Both localpart folds surfaced together (changeset 291) — withLocalpart (ensureAccount)
        // and readWithLocalpart (account/complete) both read localpartsOf. Blank both: these
        // tests assert on id/roles, not the exact localpart values. Non-null (see above) or the
        // eager .then(localpartsOf(...)) in withLocalpart NPEs at assembly.
        when(localparts.localpartsOf(any()))
                .thenReturn(Mono.just(new AccountLocalpartService.ResolvedLocalparts("", "")));
        // Changeset-292 defaults: the casdoor ensureAccount leg stamps (no-op Mono here) and
        // introspect reads back the sub (default: unset/legacy row → empty). Non-null stubs
        // required for the same Mockito-default-is-null reason as localpartOf above.
        when(casdoorSubs.stamp(any(), any())).thenReturn(Mono.empty());
        when(casdoorSubs.casdoorSubOf(any())).thenReturn(Mono.empty());
        // Changeset-301 defaults, same rationale as the 292 pair above: the casdoor
        // ensureAccount leg stamps (no-op Mono) and introspect reads back the account's
        // validated issuer (default: unset/legacy/untrusted row → empty, i.e. the pre-301
        // fail-closed shape user-bff must degrade to).
        when(accountIssuers.stamp(any(), any())).thenReturn(Mono.empty());
        when(accountIssuers.issuerOf(any())).thenReturn(Mono.empty());
    }

    private static Account acct(boolean complete) {
        return new Account("google:a@x.com", "google", "a@x.com", complete, List.of("user"));
    }

    /** Build a loaded bff_session row with the given custody columns (isNew=false). */
    private static BffSession session(String token, String accessEnc, String refreshEnc,
                                      LocalDateTime accessExpiresAt) {
        return new BffSession(token, "google:a@x.com",
                LocalDateTime.now().minusHours(1), LocalDateTime.now().plusHours(1),
                false, null, null,
                accessEnc, refreshEnc, accessExpiresAt, LocalDateTime.now().minusMinutes(1));
    }

    @Test
    void ensureAccount_delegates() {
        when(accounts.ensureAccount("google", "a@x.com")).thenReturn(Mono.just(acct(false)));
        StepVerifier.create(controller.ensureAccount(new InternalAccountController.EnsureAccountRequest("google", "a@x.com")))
                .assertNext(a -> assertThat(a.id()).isEqualTo("google:a@x.com"))
                .verifyComplete();
        verify(accounts).ensureAccount("google", "a@x.com");
    }

    @Test
    void ensureAccount_accountOut_carriesBothLocalpartFolds() {
        // 291: AccountOut surfaces BOTH the Matrix fold (localpart) and the coarser Mastodon
        // fold (mastodonLocalpart) so user-bff mints EACH platform under its own canonical,
        // collision-checked value — never a client-side re-fold.
        when(accounts.ensureAccount("google", "a@x.com")).thenReturn(Mono.just(acct(true)));
        when(localparts.localpartsOf("google:a@x.com")).thenReturn(
                Mono.just(new AccountLocalpartService.ResolvedLocalparts("a.dot", "a_dot")));
        StepVerifier.create(controller.ensureAccount(
                        new InternalAccountController.EnsureAccountRequest("google", "a@x.com")))
                .assertNext(a -> {
                    assertThat(a.localpart()).isEqualTo("a.dot");
                    assertThat(a.mastodonLocalpart()).isEqualTo("a_dot");
                })
                .verifyComplete();
    }

    /**
     * Gap-2 close (adversarial round-1-review finding, HIGH): every OTHER test in this
     * class stubs {@link AccountLocalpartService#resolveAndPersist} as always-succeeding
     * ({@code setUp()}'s default), so {@link InternalAccountController#withLocalpart}'s
     * error-mapping branch (a genuine {@link AccountLocalpartService.CollisionException} →
     * 409) was never exercised anywhere in this repo's test suite. This test overrides
     * that default for ONE call to prove the mapping itself is correct — the underlying
     * collision behaviour (the DB UNIQUE constraint + service check-then-write logic
     * actually rejecting a colliding write) is proven end-to-end against a REAL
     * Testcontainers Postgres by {@code AccountLocalpartServiceTest} and {@code
     * AuthControllerTest}'s registration-collision tests, NOT by this mock-based class.
     */
    @Test
    void ensureAccount_collision_mapsToConflict409() {
        when(accounts.ensureAccount("google", "second@x.com")).thenReturn(Mono.just(
                new Account("google:second@x.com", "google", "second@x.com", false, List.of("user"))));
        when(localparts.resolveAndPersist("google:second@x.com", "second@x.com"))
                .thenReturn(Mono.error(new AccountLocalpartService.CollisionException("collideone")));

        StepVerifier.create(controller.ensureAccount(
                        new InternalAccountController.EnsureAccountRequest("google", "second@x.com")))
                .verifyErrorSatisfies(e -> {
                    assertThat(e).isInstanceOf(ResponseStatusException.class);
                    ResponseStatusException rse = (ResponseStatusException) e;
                    assertThat(rse.getStatusCode()).isEqualTo(HttpStatusCode.valueOf(409));
                    assertThat(rse.getReason()).contains("collideone");
                });
    }

    /** Unsigned test JWT: {header}.{payload}.{signature} — decode-only, never verified here
     *  (mirrors the real id_token, which arrives already-trusted over the internal surface). */
    private static String fakeIdToken(String payloadJson) {
        String header = Base64.getUrlEncoder().withoutPadding()
                .encodeToString("{\"alg\":\"none\"}".getBytes());
        String payload = Base64.getUrlEncoder().withoutPadding().encodeToString(payloadJson.getBytes());
        return header + "." + payload + ".sig";
    }

    @Test
    void ensureAccount_casdoor_extractsSubjectAndNormalizesRoles() {
        String idToken = fakeIdToken(
                "{\"email\":\"e2e-admin@hugmesh.net\","
                        + "\"roles\":[\"ROLE_ADMIN\",\"ROLE_USER\"]}");
        when(accounts.ensureAccount(eq("casdoor"), eq("e2e-admin@hugmesh.net"), any()))
                .thenReturn(Mono.just(acct(true)));
        StepVerifier.create(controller.ensureAccount(
                        new InternalAccountController.EnsureAccountRequest("casdoor", idToken)))
                .expectNextCount(1)
                .verifyComplete();
        // ROLE_ADMIN/ROLE_USER (gateway-facing convention) -> admin/user (BFF session convention).
        verify(accounts).ensureAccount("casdoor", "e2e-admin@hugmesh.net", List.of("admin", "user"));
    }

    @Test
    void ensureAccount_casdoor_rolesClaimAsObjectsWithNameField() {
        String idToken = fakeIdToken(
                "{\"sub\":\"e2e-mod\",\"roles\":[{\"name\":\"ROLE_MOD\"},{\"name\":\"ROLE_USER\"}]}");
        when(accounts.ensureAccount(eq("casdoor"), eq("e2e-mod"), any())).thenReturn(Mono.just(acct(true)));
        StepVerifier.create(controller.ensureAccount(
                        new InternalAccountController.EnsureAccountRequest("casdoor", idToken)))
                .expectNextCount(1)
                .verifyComplete();
        verify(accounts).ensureAccount("casdoor", "e2e-mod", List.of("mod", "user"));
    }

    @Test
    void ensureAccount_casdoor_doublePrefixedRoleNormalizesToBareLowercase() {
        // Defensive parity with the gateway's Roles.canonicalRoleName() double-prefix guard.
        String idToken = fakeIdToken("{\"sub\":\"e2e-superadmin\",\"roles\":[\"ROLE_ROLE_SUPERADMIN\"]}");
        when(accounts.ensureAccount(eq("casdoor"), eq("e2e-superadmin"), any())).thenReturn(Mono.just(acct(true)));
        StepVerifier.create(controller.ensureAccount(
                        new InternalAccountController.EnsureAccountRequest("casdoor", idToken)))
                .expectNextCount(1)
                .verifyComplete();
        verify(accounts).ensureAccount("casdoor", "e2e-superadmin", List.of("superadmin"));
    }

    @Test
    void ensureAccount_casdoor_missingRolesClaim_fallsBackToEmptyList() {
        String idToken = fakeIdToken("{\"sub\":\"e2e-user\"}");
        when(accounts.ensureAccount(eq("casdoor"), eq("e2e-user"), any())).thenReturn(Mono.just(acct(true)));
        StepVerifier.create(controller.ensureAccount(
                        new InternalAccountController.EnsureAccountRequest("casdoor", idToken)))
                .expectNextCount(1)
                .verifyComplete();
        // Empty list (not null) — AccountStore.ensureAccount treats empty as "no roles to sync"
        // and falls back to its own legacy default.
        verify(accounts).ensureAccount("casdoor", "e2e-user", List.of());
    }

    @Test
    void ensureAccount_casdoor_duplicateRolesClaimEntriesDeduped() {
        // Casdoor can list the same role twice (direct grant + group membership).
        String idToken = fakeIdToken(
                "{\"sub\":\"e2e-admin\",\"roles\":[\"ROLE_ADMIN\",\"ROLE_USER\",\"ROLE_ADMIN\",\"ROLE_USER\"]}");
        when(accounts.ensureAccount(eq("casdoor"), eq("e2e-admin"), any())).thenReturn(Mono.just(acct(true)));
        StepVerifier.create(controller.ensureAccount(
                        new InternalAccountController.EnsureAccountRequest("casdoor", idToken)))
                .expectNextCount(1)
                .verifyComplete();
        verify(accounts).ensureAccount("casdoor", "e2e-admin", List.of("admin", "user"));
    }

    // ── issue #14: the `roles` claim is bounded before AccountStore CSV-joins it ──

    @Test
    void ensureAccount_casdoor_overLongRoleStringIsDroppedNotTruncated() {
        // One absurd entry must not reach the CSV join — and must not take the legitimate
        // roles either side of it down with it. Dropped whole: a truncated role string
        // would be a DIFFERENT role than the one the claim named.
        String huge = "x".repeat(200);
        String idToken = fakeIdToken(
                "{\"sub\":\"e2e-admin\",\"roles\":[\"ROLE_ADMIN\",\"" + huge + "\",\"ROLE_USER\"]}");
        when(accounts.ensureAccount(eq("casdoor"), eq("e2e-admin"), any())).thenReturn(Mono.just(acct(true)));
        StepVerifier.create(controller.ensureAccount(
                        new InternalAccountController.EnsureAccountRequest("casdoor", idToken)))
                .expectNextCount(1)
                .verifyComplete();
        verify(accounts).ensureAccount("casdoor", "e2e-admin", List.of("admin", "user"));
    }

    @Test
    void ensureAccount_casdoor_roleLengthCapBoundary_keepsExactlyAtTheCapDropsOverIt() {
        // MAX_ROLE_LENGTH is 64, measured AFTER normalizeRole strips the ROLE_ prefix.
        String atCap = "a".repeat(64);
        String overCap = "b".repeat(65);
        String idToken = fakeIdToken("{\"sub\":\"e2e-edge\",\"roles\":[\"ROLE_" + atCap
                + "\",\"ROLE_" + overCap + "\"]}");
        when(accounts.ensureAccount(eq("casdoor"), eq("e2e-edge"), any())).thenReturn(Mono.just(acct(true)));
        StepVerifier.create(controller.ensureAccount(
                        new InternalAccountController.EnsureAccountRequest("casdoor", idToken)))
                .expectNextCount(1)
                .verifyComplete();
        verify(accounts).ensureAccount("casdoor", "e2e-edge", List.of(atCap));
    }

    @Test
    void ensureAccount_casdoor_manyRolesCappedSoTheJoinedCsvFitsTheAccountRolesColumn() {
        // account.roles is varchar(255) (changeset 004) and AccountStore.ensureAccount writes
        // String.join(",", roles) into it — an unbounded claim would fail that INSERT, i.e.
        // fail the login. First-seen-wins: the surviving prefix stays in claim order.
        String many = IntStream.range(0, 500)
                .mapToObj(i -> "\"ROLE_R" + i + "\"")
                .collect(Collectors.joining(","));
        String idToken = fakeIdToken("{\"sub\":\"e2e-many\",\"roles\":[" + many + "]}");
        when(accounts.ensureAccount(eq("casdoor"), eq("e2e-many"), any())).thenReturn(Mono.just(acct(true)));
        StepVerifier.create(controller.ensureAccount(
                        new InternalAccountController.EnsureAccountRequest("casdoor", idToken)))
                .expectNextCount(1)
                .verifyComplete();
        @SuppressWarnings("unchecked")
        ArgumentCaptor<List<String>> captor = ArgumentCaptor.forClass(List.class);
        verify(accounts).ensureAccount(eq("casdoor"), eq("e2e-many"), captor.capture());
        List<String> synced = captor.getValue();
        assertThat(String.join(",", synced)).hasSizeLessThanOrEqualTo(255);
        assertThat(synced).isNotEmpty().startsWith("r0", "r1", "r2");
    }

    @Test
    void ensureAccount_casdoor_rolesClaimEntriesPastTheScanCapAreIgnored() {
        // MAX_ROLE_CLAIM_ENTRIES is 64 and bounds the SCAN, not just what is admitted — so
        // entries that cost no CSV width (here, 70 duplicates) still consume the scan cap,
        // and the distinct role sitting behind them is never reached.
        String padding = IntStream.range(0, 70)
                .mapToObj(i -> "\"ROLE_USER\"")
                .collect(Collectors.joining(","));
        String idToken = fakeIdToken(
                "{\"sub\":\"e2e-scan\",\"roles\":[" + padding + ",\"ROLE_ADMIN\"]}");
        when(accounts.ensureAccount(eq("casdoor"), eq("e2e-scan"), any())).thenReturn(Mono.just(acct(true)));
        StepVerifier.create(controller.ensureAccount(
                        new InternalAccountController.EnsureAccountRequest("casdoor", idToken)))
                .expectNextCount(1)
                .verifyComplete();
        verify(accounts).ensureAccount("casdoor", "e2e-scan", List.of("user"));
    }

    // ── changeset 292: the Casdoor `sub` UUID stamp (A5 part-B route-pin fix) ──

    @Test
    void ensureAccount_casdoor_stampsRawSubUuid_evenWhenEmailWinsTheSubjectPrecedence() {
        // THE A5 part-B shape: email wins the account-key precedence, so the account id is
        // "casdoor:<email>" and the UUID is NOT derivable from it — the raw `sub` claim must
        // be stamped separately or a UUID-form route pin can never match this account's
        // bff_ sessions at the gateway.
        String idToken = fakeIdToken(
                "{\"sub\":\"2f3a9c1e-7b4d-4e08-9a21-5c6d7e8f9a0b\",\"email\":\"a@x.com\"}");
        when(accounts.ensureAccount(eq("casdoor"), eq("a@x.com"), any()))
                .thenReturn(Mono.just(new Account("casdoor:a@x.com", "casdoor", "a@x.com",
                        true, List.of("user"))));
        StepVerifier.create(controller.ensureAccount(
                        new InternalAccountController.EnsureAccountRequest("casdoor", idToken)))
                .expectNextCount(1)
                .verifyComplete();
        verify(casdoorSubs).stamp("casdoor:a@x.com", "2f3a9c1e-7b4d-4e08-9a21-5c6d7e8f9a0b");
    }

    @Test
    void ensureAccount_casdoor_noSubClaim_noStamp_loginStillSucceeds() {
        // Degenerate id_token with no sub claim: never fail the login over it, and never
        // call stamp with a value (stamp(null) is a documented no-op, but the extraction
        // already yields null so the stamp receives null — assert it is null, i.e. nothing
        // real is ever stamped from a subless token).
        String idToken = fakeIdToken("{\"email\":\"a@x.com\"}");
        when(accounts.ensureAccount(eq("casdoor"), eq("a@x.com"), any()))
                .thenReturn(Mono.just(acct(true)));
        StepVerifier.create(controller.ensureAccount(
                        new InternalAccountController.EnsureAccountRequest("casdoor", idToken)))
                .expectNextCount(1)
                .verifyComplete();
        verify(casdoorSubs).stamp(any(), org.mockito.ArgumentMatchers.isNull());
    }

    @Test
    void ensureAccount_nonCasdoorProvider_neverStamps() {
        // The invite providers (google/discord) carry no Casdoor id_token — the stamp leg
        // must not run at all (their rows legitimately stay casdoor_sub = null).
        when(accounts.ensureAccount("google", "a@x.com")).thenReturn(Mono.just(acct(false)));
        StepVerifier.create(controller.ensureAccount(
                        new InternalAccountController.EnsureAccountRequest("google", "a@x.com")))
                .expectNextCount(1)
                .verifyComplete();
        verify(casdoorSubs, never()).stamp(any(), any());
        verify(accountIssuers, never()).stamp(any(), any());
    }

    // ── ensureAccount issuer stamp (changeset 301 — the multi-brand domain-scope fix) ──

    @Test
    void ensureAccount_casdoor_handsRawIssClaimToTheIssuerStamp() {
        // The controller's job is ONLY to decode + hand over the raw iss; the trust decision
        // belongs to AccountIssuerService (which is why it, not this class, owns the forged-iss
        // test). Assert the exact decoded claim reaches stamp() — a controller that dropped or
        // rewrote it would silently break the brand binding.
        String idToken = fakeIdToken(
                "{\"sub\":\"2f3a9c1e-7b4d-4e08-9a21-5c6d7e8f9a0b\",\"email\":\"a@x.com\","
                        + "\"iss\":\"https://casdoor-brandx.example.tld\"}");
        when(accounts.ensureAccount(eq("casdoor"), eq("a@x.com"), any()))
                .thenReturn(Mono.just(new Account("casdoor:a@x.com", "casdoor", "a@x.com",
                        true, List.of("user"))));
        StepVerifier.create(controller.ensureAccount(
                        new InternalAccountController.EnsureAccountRequest("casdoor", idToken)))
                .expectNextCount(1)
                .verifyComplete();
        verify(accountIssuers).stamp("casdoor:a@x.com", "https://casdoor-brandx.example.tld");
    }

    @Test
    void ensureAccount_casdoor_noIssClaim_noStamp_loginStillSucceeds() {
        // Degenerate id_token with no iss claim: never fail the login over it. The extraction
        // yields null, and stamp(null) is a documented no-op that never clears a previously
        // VERIFIED brand binding.
        String idToken = fakeIdToken("{\"email\":\"a@x.com\"}");
        when(accounts.ensureAccount(eq("casdoor"), eq("a@x.com"), any()))
                .thenReturn(Mono.just(acct(true)));
        StepVerifier.create(controller.ensureAccount(
                        new InternalAccountController.EnsureAccountRequest("casdoor", idToken)))
                .expectNextCount(1)
                .verifyComplete();
        verify(accountIssuers).stamp(any(), org.mockito.ArgumentMatchers.isNull());
    }

    @Test
    void account_found_and_notFound() {
        when(accounts.account("google:a@x.com")).thenReturn(Mono.just(acct(true)));
        StepVerifier.create(controller.account("google:a@x.com"))
                .assertNext(a -> assertThat(a.registrationComplete()).isTrue())
                .verifyComplete();

        when(accounts.account("missing")).thenReturn(Mono.empty());
        StepVerifier.create(controller.account("missing"))
                .verifyErrorSatisfies(e -> assertThat(((ResponseStatusException) e).getStatusCode()).isEqualTo(HttpStatusCode.valueOf(404)));
    }

    @Test
    void complete_marksComplete_orNotFound() {
        when(accounts.account("google:a@x.com")).thenReturn(Mono.just(acct(false)));
        when(accounts.markComplete(any())).thenReturn(Mono.just(acct(true)));
        StepVerifier.create(controller.complete("google:a@x.com"))
                .assertNext(a -> assertThat(a.registrationComplete()).isTrue())
                .verifyComplete();
        verify(accounts).markComplete(any());

        when(accounts.account("missing")).thenReturn(Mono.empty());
        StepVerifier.create(controller.complete("missing"))
                .verifyErrorSatisfies(e -> assertThat(((ResponseStatusException) e).getStatusCode()).isEqualTo(HttpStatusCode.valueOf(404)));
    }

    @Test
    void restartOnboarding_resetsRegistrationComplete_andReadsBackTheLocalpart() {
        // The persisted localpart is READ (localpartsOf), never re-resolved: restart-onboarding is
        // the mirror of complete(), not an account-creation call site.
        when(localparts.localpartsOf("google:a@x.com")).thenReturn(Mono.just(
                new AccountLocalpartService.ResolvedLocalparts("alice", "alice_m")));
        when(accounts.account("google:a@x.com")).thenReturn(Mono.just(acct(true)));
        when(accounts.restartOnboarding(any())).thenReturn(Mono.just(acct(false)));

        StepVerifier.create(controller.restartOnboarding("google:a@x.com"))
                .assertNext(a -> {
                    assertThat(a.id()).isEqualTo("google:a@x.com");
                    assertThat(a.registrationComplete()).isFalse();
                    assertThat(a.localpart()).isEqualTo("alice");
                    assertThat(a.mastodonLocalpart()).isEqualTo("alice_m");
                })
                .verifyComplete();

        verify(accounts).restartOnboarding(acct(true));
        verify(accounts, never()).markComplete(any());
        verify(localparts, never()).resolveAndPersist(any(), any());
    }

    @Test
    void restartOnboarding_unknownAccount_is404_andNothingIsWritten() {
        when(accounts.account("missing")).thenReturn(Mono.empty());
        StepVerifier.create(controller.restartOnboarding("missing"))
                .verifyErrorSatisfies(e -> assertThat(((ResponseStatusException) e).getStatusCode()).isEqualTo(HttpStatusCode.valueOf(404)));
        verify(accounts, never()).restartOnboarding(any());
    }

    @Test
    void allowlist_perProvider_andUnknown() {
        // No domain supplied -> the resolver's fallback, which on this untenanted wiring is
        // AccountStore.DEFAULT_DOMAIN. The gate is the DOMAIN-SCOPED overload either way.
        when(accounts.isEmailInvited("a@x.com", AccountStore.DEFAULT_DOMAIN)).thenReturn(Mono.just(true));
        StepVerifier.create(controller.allowlist("google", "a@x.com", null))
                .assertNext(m -> assertThat(m.get("invited")).isTrue())
                .verifyComplete();

        when(accounts.isDiscordInvited("bob", AccountStore.DEFAULT_DOMAIN)).thenReturn(Mono.just(false));
        StepVerifier.create(controller.allowlist("discord", "bob", null))
                .assertNext(m -> assertThat(m.get("invited")).isFalse())
                .verifyComplete();

        StepVerifier.create(controller.allowlist("steam", "x", null))
                .verifyErrorSatisfies(e -> assertThat(((ResponseStatusException) e).getStatusCode()).isEqualTo(HttpStatusCode.valueOf(400)));
        // Never the cross-brand-permissive 1-arg overloads (auth-core issue #1).
        verify(accounts, never()).isEmailInvited(any());
        verify(accounts, never()).isDiscordInvited(any());
    }

    /**
     * auth-core issue #1 at the INTERNAL call site: the trusted in-cluster caller's
     * {@code domain} reaches the store verbatim, so brand X's invite is never consulted for a
     * brand Y lookup. Before the fix this endpoint asked "invited in ANY domain" and the
     * {@code domain} argument did not exist.
     *
     * <p>The controller here is wired to a TWO-BRAND deployment ({@code brand-a} +
     * {@code brand-b}), not the class-level untenanted resolver. Since issue #47
     * {@link RegistrationDomainResolver#forInternalCaller} only honours a brand this
     * deployment serves and fails closed to {@code PrincipalDomain.NO_DOMAIN} on any other, so
     * on the untenanted wiring {@code "brand-a"} would never reach the store (issue #103). The
     * fail-closed half of that contract is pinned in {@code RegistrationDomainResolverTest}.
     */
    @Test
    void allowlist_honoursCallerSuppliedDomain() {
        RegistrationDomainResolver twoBrands = new RegistrationDomainResolver(
                new net.hugmesh.commons.security.DomainRegistry("",
                        "https://id.brand-a.test=brand-a,https://id.brand-b.test=brand-b"), "");
        InternalAccountController tenanted = new InternalAccountController(
                accounts, suspensions, mfaStepUp, CIPHER, oidc, 60L, localparts, casdoorSubs,
                accountIssuers, twoBrands, usage);
        when(accounts.isEmailInvited("a@x.com", "brand-a")).thenReturn(Mono.just(true));
        when(accounts.isEmailInvited("a@x.com", "brand-b")).thenReturn(Mono.just(false));

        StepVerifier.create(tenanted.allowlist("google", "a@x.com", "brand-a"))
                .assertNext(m -> assertThat(m.get("invited")).isTrue())
                .verifyComplete();
        StepVerifier.create(tenanted.allowlist("google", "a@x.com", "brand-b"))
                .assertNext(m -> assertThat(m.get("invited")).isFalse())
                .verifyComplete();

        verify(accounts).isEmailInvited("a@x.com", "brand-a");
        verify(accounts).isEmailInvited("a@x.com", "brand-b");
    }

    /** A blank/whitespace {@code domain} is treated as OMITTED (falls back), never passed
     *  through as a literal that would silently match no row and read as "not invited". */
    @Test
    void allowlist_blankDomain_fallsBack() {
        when(accounts.isEmailInvited("a@x.com", AccountStore.DEFAULT_DOMAIN)).thenReturn(Mono.just(true));
        StepVerifier.create(controller.allowlist("google", "a@x.com", "   "))
                .assertNext(m -> assertThat(m.get("invited")).isTrue())
                .verifyComplete();
        verify(accounts).isEmailInvited("a@x.com", AccountStore.DEFAULT_DOMAIN);
    }

    @Test
    void createSession_mintsToken_orNotFound() {
        when(accounts.account("google:a@x.com")).thenReturn(Mono.just(acct(true)));
        when(accounts.newSession(any())).thenReturn(Mono.just("bff_abc123"));
        StepVerifier.create(controller.createSession(new InternalAccountController.CreateSessionRequest("google:a@x.com")))
                .assertNext(m -> assertThat(m.get("token")).isEqualTo("bff_abc123"))
                .verifyComplete();

        when(accounts.account("missing")).thenReturn(Mono.empty());
        StepVerifier.create(controller.createSession(new InternalAccountController.CreateSessionRequest("missing")))
                .verifyErrorSatisfies(e -> assertThat(((ResponseStatusException) e).getStatusCode()).isEqualTo(HttpStatusCode.valueOf(404)));
    }

    @Test
    void deleteSession_isIdempotent204() {
        when(accounts.deleteSession("bff_abc")).thenReturn(Mono.just("bff_abc"));
        StepVerifier.create(controller.deleteSession("bff_abc"))
                .assertNext(r -> assertThat(r.getStatusCode()).isEqualTo(HttpStatusCode.valueOf(204)))
                .verifyComplete();
        verify(accounts).deleteSession("bff_abc");
    }

    @Test
    void sessionsForAccount_listsLiveRows_newestFirst() {
        // Live-only + newest-first ordering is auth-core's contract (sessionsForAccount filters
        // expires_at>now() and orders created_at desc); the controller is a thin pass-through, so
        // assert it streams exactly what the store returns, in order, by the requested accountId.
        LocalDateTime now = LocalDateTime.now();
        BffSessionRow newer = new BffSessionRow("bff_newer", "google:a@x.com",
                now.minusMinutes(5), now.plusHours(1));
        BffSessionRow older = new BffSessionRow("bff_older", "google:a@x.com",
                now.minusHours(2), now.plusMinutes(30));
        when(accounts.sessionsForAccount("google:a@x.com")).thenReturn(Flux.just(newer, older));

        StepVerifier.create(controller.sessionsForAccount("google:a@x.com"))
                .assertNext(r -> {
                    assertThat(r.token()).isEqualTo("bff_newer");
                    assertThat(r.accountId()).isEqualTo("google:a@x.com");
                })
                .assertNext(r -> assertThat(r.token()).isEqualTo("bff_older"))
                .verifyComplete();
        verify(accounts).sessionsForAccount("google:a@x.com");
    }

    @Test
    void sessionsForAccount_unknownAccount_emptyStream() {
        // Absent account / no live sessions are indistinguishable + benign for this read → empty
        // stream (the HTTP layer renders []), never a 404.
        when(accounts.sessionsForAccount("missing")).thenReturn(Flux.empty());
        StepVerifier.create(controller.sessionsForAccount("missing"))
                .verifyComplete();
        verify(accounts).sessionsForAccount("missing");
    }

    @Test
    void namespaces_found_orNotFound() {
        when(accounts.account("google:a@x.com")).thenReturn(Mono.just(acct(true)));
        when(accounts.namespacesFor(any())).thenReturn(Mono.just(List.of("matrix", "mastodon")));
        StepVerifier.create(controller.namespaces("google:a@x.com"))
                .assertNext(m -> assertThat(m.get("namespaces")).containsExactly("matrix", "mastodon"))
                .verifyComplete();

        when(accounts.account("missing")).thenReturn(Mono.empty());
        StepVerifier.create(controller.namespaces("missing"))
                .verifyErrorSatisfies(e -> assertThat(((ResponseStatusException) e).getStatusCode()).isEqualTo(HttpStatusCode.valueOf(404)));
    }

    // ──────────────────────────── custody/stamp (band-180) ────────────────────────────

    @Test
    void stamp_storesCiphertextAsIs_204() {
        // The blobs arrive ALREADY ciphertext from user-bff; admin-bff stores them verbatim
        // (no re-encryption). Assert the EXACT (token, encAccess, encRefresh) pass-through + an
        // accessExpiresAt ≈ now + expiresInSeconds.
        when(accounts.stampCustody(eq("bff_abc"), eq("ENC-ACCESS"), eq("ENC-REFRESH"), any()))
                .thenReturn(Mono.just(1L));
        LocalDateTime before = LocalDateTime.now().plusSeconds(900);
        StepVerifier.create(controller.stampCustody(new InternalAccountController.StampCustodyRequest(
                        "bff_abc", "ENC-ACCESS", "ENC-REFRESH", 900)))
                .verifyComplete();
        LocalDateTime after = LocalDateTime.now().plusSeconds(900);
        verify(accounts).stampCustody(eq("bff_abc"), eq("ENC-ACCESS"), eq("ENC-REFRESH"),
                org.mockito.ArgumentMatchers.argThat(exp ->
                        exp != null && !exp.isBefore(before.minusSeconds(2)) && !exp.isAfter(after.plusSeconds(2))));
    }

    @Test
    void stamp_nullRefreshTolerated_204() {
        when(accounts.stampCustody(eq("bff_abc"), eq("ENC-ACCESS"), eq(null), any()))
                .thenReturn(Mono.just(1L));
        StepVerifier.create(controller.stampCustody(new InternalAccountController.StampCustodyRequest(
                        "bff_abc", "ENC-ACCESS", null, 900)))
                .verifyComplete();
        verify(accounts).stampCustody(eq("bff_abc"), eq("ENC-ACCESS"), eq(null), any());
    }

    @Test
    void stamp_unknownSession_404() {
        // rows updated == 0 → the session token is unknown / non-bff.
        when(accounts.stampCustody(eq("bff_nope"), any(), any(), any())).thenReturn(Mono.just(0L));
        StepVerifier.create(controller.stampCustody(new InternalAccountController.StampCustodyRequest(
                        "bff_nope", "ENC-ACCESS", "ENC-REFRESH", 900)))
                .verifyErrorSatisfies(e -> assertThat(((ResponseStatusException) e).getStatusCode())
                        .isEqualTo(HttpStatusCode.valueOf(404)));
    }

    // ──────────────────────────── session/exchange (band-180) ────────────────────────────

    @Test
    void exchange_cipherUnavailable_503() {
        // INERT cipher (no key) → fail-closed 503 BEFORE any store read.
        InternalAccountController inert = new InternalAccountController(
                accounts, suspensions, mfaStepUp, INERT_CIPHER, oidc, 60L, localparts, casdoorSubs,
                accountIssuers, registrationDomains, usage);
        StepVerifier.create(inert.exchange(new InternalAccountController.ExchangeRequest("bff_x")))
                .verifyErrorSatisfies(e -> assertThat(((ResponseStatusException) e).getStatusCode())
                        .isEqualTo(HttpStatusCode.valueOf(503)));
        verify(accounts, never()).sessionRow(any());
    }

    @Test
    void exchange_nullCipherBean_503() {
        // A null cipher bean is also fail-closed 503 (the @Nullable null-guard).
        InternalAccountController noCipher = new InternalAccountController(
                accounts, suspensions, mfaStepUp, null, oidc, 60L, localparts, casdoorSubs,
                accountIssuers, registrationDomains, usage);
        StepVerifier.create(noCipher.exchange(new InternalAccountController.ExchangeRequest("bff_x")))
                .verifyErrorSatisfies(e -> assertThat(((ResponseStatusException) e).getStatusCode())
                        .isEqualTo(HttpStatusCode.valueOf(503)));
    }

    @Test
    void exchange_sessionNotFound_404() {
        when(accounts.sessionRow("bff_missing")).thenReturn(Mono.empty());
        StepVerifier.create(controller.exchange(new InternalAccountController.ExchangeRequest("bff_missing")))
                .verifyErrorSatisfies(e -> assertThat(((ResponseStatusException) e).getStatusCode())
                        .isEqualTo(HttpStatusCode.valueOf(404)));
    }

    @Test
    void exchange_validNonExpiring_returnsDecryptedBearer_noRefresh() {
        // Far expiry → no refresh; decrypt round-trips the real cipher; oidc never called.
        String encAccess = CIPHER.encrypt("ACCESS-JWT");
        when(accounts.sessionRow("bff_ok"))
                .thenReturn(Mono.just(session("bff_ok", encAccess, null, LocalDateTime.now().plusHours(2))));
        StepVerifier.create(controller.exchange(new InternalAccountController.ExchangeRequest("bff_ok")))
                .assertNext(m -> assertThat(m.get("bearer")).isEqualTo("ACCESS-JWT"))
                .verifyComplete();
        verify(oidc, never()).refresh(any());
    }

    @Test
    void exchange_nearExpiry_refreshesAndReStamps_returnsNewBearer() {
        // Near-expiry + refresh present + oidc bean present → refresh + re-stamp + NEW bearer.
        String encAccess = CIPHER.encrypt("OLD-ACCESS");
        String encRefresh = CIPHER.encrypt("REFRESH-TOKEN");
        when(accounts.sessionRow("bff_near"))
                .thenReturn(Mono.just(session("bff_near", encAccess, encRefresh, LocalDateTime.now().plusSeconds(10))));
        when(oidc.refresh("REFRESH-TOKEN"))
                .thenReturn(Mono.just(new OidcTokens("NEW-ACCESS", "NEW-REFRESH", "id", 3600)));
        when(accounts.stampCustody(eq("bff_near"), any(), any(), any())).thenReturn(Mono.just(1L));
        StepVerifier.create(controller.exchange(new InternalAccountController.ExchangeRequest("bff_near")))
                .assertNext(m -> assertThat(m.get("bearer")).isEqualTo("NEW-ACCESS"))
                .verifyComplete();
        verify(oidc).refresh("REFRESH-TOKEN");
        verify(accounts).stampCustody(eq("bff_near"), any(), any(), any());
    }

    @Test
    void exchange_decryptNull_401() {
        // A bogus enc blob the cipher cannot decrypt → fail-closed 401 (the gateway then rejects).
        when(accounts.sessionRow("bff_tampered"))
                .thenReturn(Mono.just(session("bff_tampered", "not-a-valid-ciphertext-blob", null,
                        LocalDateTime.now().plusHours(2))));
        StepVerifier.create(controller.exchange(new InternalAccountController.ExchangeRequest("bff_tampered")))
                .verifyErrorSatisfies(e -> assertThat(((ResponseStatusException) e).getStatusCode())
                        .isEqualTo(HttpStatusCode.valueOf(401)));
    }

    @Test
    void exchange_refreshError_servesStillValidCurrent_no401() {
        // Near-expiry, refresh present, but the refresh leg ERRORS — the current access is still
        // cryptographically valid, so serve it (NOT a hard 401).
        String encAccess = CIPHER.encrypt("STILL-VALID-ACCESS");
        String encRefresh = CIPHER.encrypt("REFRESH-TOKEN");
        when(accounts.sessionRow("bff_softfail"))
                .thenReturn(Mono.just(session("bff_softfail", encAccess, encRefresh, LocalDateTime.now().plusSeconds(10))));
        when(oidc.refresh("REFRESH-TOKEN"))
                .thenReturn(Mono.error(new IllegalStateException("token endpoint 500")));
        StepVerifier.create(controller.exchange(new InternalAccountController.ExchangeRequest("bff_softfail")))
                .assertNext(m -> assertThat(m.get("bearer")).isEqualTo("STILL-VALID-ACCESS"))
                .verifyComplete();
        verify(accounts, never()).stampCustody(any(), any(), any(), any());
    }

    // ──────────────────────────── session/introspect (gateway bridge) ─────────────────────────

    @Test
    void introspect_noHeader_401() {
        StepVerifier.create(controller.introspect(null))
                .verifyErrorSatisfies(e -> assertThat(((ResponseStatusException) e).getStatusCode())
                        .isEqualTo(HttpStatusCode.valueOf(401)));
    }

    @Test
    void introspect_unknownToken_401() {
        when(accounts.sessionOf("Bearer bff_unknown")).thenReturn(Mono.empty());
        StepVerifier.create(controller.introspect("Bearer bff_unknown"))
                .verifyErrorSatisfies(e -> assertThat(((ResponseStatusException) e).getStatusCode())
                        .isEqualTo(HttpStatusCode.valueOf(401)));
    }

    @Test
    void introspect_validToken_activeAccount_mfaFalse() {
        Account a = acct(true);
        when(accounts.sessionOf("Bearer bff_ok")).thenReturn(Mono.just(a));
        when(suspensions.statusFor("a@x.com")).thenReturn(Mono.just(AccountStatus.active()));
        when(accounts.mfaStateOf("bff_ok")).thenReturn(Mono.empty());

        StepVerifier.create(controller.introspect("Bearer bff_ok"))
                .assertNext(r -> {
                    assertThat(r.id()).isEqualTo("google:a@x.com");
                    assertThat(r.provider()).isEqualTo("google");
                    assertThat(r.roles()).containsExactly("user");
                    assertThat(r.registrationComplete()).isTrue();
                    assertThat(r.status()).isEqualTo(AccountStatus.ACTIVE);
                    assertThat(r.mfaSatisfied()).isFalse();
                })
                .verifyComplete();
    }

    @Test
    void introspect_validToken_mfaSatisfied() {
        Account a = acct(true);
        when(accounts.sessionOf("Bearer bff_mfa")).thenReturn(Mono.just(a));
        when(suspensions.statusFor("a@x.com")).thenReturn(Mono.just(AccountStatus.active()));
        when(accounts.mfaStateOf("bff_mfa"))
                .thenReturn(Mono.just(new AccountStore.MfaState(true, LocalDateTime.now())));

        StepVerifier.create(controller.introspect("Bearer bff_mfa"))
                .assertNext(r -> assertThat(r.mfaSatisfied()).isTrue())
                .verifyComplete();
    }

    @Test
    void introspect_staleMfaStamp_reportsNotSatisfied_windowApplied() {
        // A step-up older than the 10m freshness window must report mfaSatisfied=FALSE, so the
        // gateway's presence-based bff_ MFA floor cannot be cleared by a stale native-login
        // session (the D8 privileged-floor bypass). Pre-fix this returned the raw column -> true.
        Account a = acct(true);
        when(accounts.sessionOf("Bearer bff_stale")).thenReturn(Mono.just(a));
        when(suspensions.statusFor("a@x.com")).thenReturn(Mono.just(AccountStatus.active()));
        when(accounts.mfaStateOf("bff_stale"))
                .thenReturn(Mono.just(new AccountStore.MfaState(true, LocalDateTime.now().minusMinutes(30))));

        StepVerifier.create(controller.introspect("Bearer bff_stale"))
                .assertNext(r -> assertThat(r.mfaSatisfied()).isFalse())
                .verifyComplete();
    }

    @Test
    void introspect_mfaSatisfiedTrueButNoTimestamp_failsClosed() {
        // satisfied flag true but null timestamp -> freshness unprovable -> report false.
        Account a = acct(true);
        when(accounts.sessionOf("Bearer bff_nots")).thenReturn(Mono.just(a));
        when(suspensions.statusFor("a@x.com")).thenReturn(Mono.just(AccountStatus.active()));
        when(accounts.mfaStateOf("bff_nots"))
                .thenReturn(Mono.just(new AccountStore.MfaState(true, null)));

        StepVerifier.create(controller.introspect("Bearer bff_nots"))
                .assertNext(r -> assertThat(r.mfaSatisfied()).isFalse())
                .verifyComplete();
    }

    @Test
    void introspect_suspendedAccount_statusReflected() {
        Account a = acct(true);
        AccountStatus suspended = new AccountStatus(AccountStatus.SUSPENDED, null, "abuse");
        when(accounts.sessionOf("Bearer bff_sus")).thenReturn(Mono.just(a));
        when(suspensions.statusFor("a@x.com")).thenReturn(Mono.just(suspended));
        when(accounts.mfaStateOf("bff_sus")).thenReturn(Mono.empty());

        StepVerifier.create(controller.introspect("Bearer bff_sus"))
                .assertNext(r -> assertThat(r.status()).isEqualTo(AccountStatus.SUSPENDED))
                .verifyComplete();
    }

    // ── introspect casdoorSub (changeset 292 — the A5 part-B route-pin fix) ──

    @Test
    void introspect_freshlyStampedAccount_carriesCasdoorSub() {
        // The gateway leg of the fix consumes THIS field: a session whose account row was
        // stamped at the native-login mint must surface the raw UUID so the gateway can
        // fold it into the route-pin identity set for the bff_ carrier.
        Account a = acct(true);
        when(accounts.sessionOf("Bearer bff_sub")).thenReturn(Mono.just(a));
        when(suspensions.statusFor("a@x.com")).thenReturn(Mono.just(AccountStatus.active()));
        when(accounts.mfaStateOf("bff_sub")).thenReturn(Mono.empty());
        when(casdoorSubs.casdoorSubOf("google:a@x.com"))
                .thenReturn(Mono.just("2f3a9c1e-7b4d-4e08-9a21-5c6d7e8f9a0b"));

        StepVerifier.create(controller.introspect("Bearer bff_sub"))
                .assertNext(r -> {
                    assertThat(r.casdoorSub()).isEqualTo("2f3a9c1e-7b4d-4e08-9a21-5c6d7e8f9a0b");
                    // The rest of the contract is untouched by the new field.
                    assertThat(r.id()).isEqualTo("google:a@x.com");
                    assertThat(r.status()).isEqualTo(AccountStatus.ACTIVE);
                })
                .verifyComplete();
    }

    @Test
    void introspect_legacyRowWithoutSub_returnsNullCasdoorSub_restOfContractUnchanged() {
        // Legacy rows (pre-292, or google/discord invite accounts) have no stamped sub:
        // introspect must return casdoorSub = null and EVERY other field exactly as before
        // — the gateway then degrades to the pre-292 identity set (no behavior change).
        Account a = acct(true);
        when(accounts.sessionOf("Bearer bff_legacy")).thenReturn(Mono.just(a));
        when(suspensions.statusFor("a@x.com")).thenReturn(Mono.just(AccountStatus.active()));
        when(accounts.mfaStateOf("bff_legacy")).thenReturn(Mono.empty());
        // setUp default: casdoorSubOf -> Mono.empty() (the unset-column read shape).

        StepVerifier.create(controller.introspect("Bearer bff_legacy"))
                .assertNext(r -> {
                    assertThat(r.casdoorSub()).isNull();
                    assertThat(r.id()).isEqualTo("google:a@x.com");
                    assertThat(r.provider()).isEqualTo("google");
                    assertThat(r.roles()).containsExactly("user");
                    assertThat(r.registrationComplete()).isTrue();
                    assertThat(r.status()).isEqualTo(AccountStatus.ACTIVE);
                    assertThat(r.mfaSatisfied()).isFalse();
                })
                .verifyComplete();
    }

    // ── introspect issuer (changeset 301 — the multi-brand domain-scope fix) ──

    @Test
    void introspect_accountWithValidatedIssuer_carriesIssuer() {
        // The user-bff leg of the fix consumes THIS field: a session whose account row holds a
        // VALIDATED issuer must surface it so the synthetic-Jwt filter can stamp the right
        // brand's iss instead of failing every domain-scoped read/write closed.
        Account a = acct(true);
        when(accounts.sessionOf("Bearer bff_iss")).thenReturn(Mono.just(a));
        when(suspensions.statusFor("a@x.com")).thenReturn(Mono.just(AccountStatus.active()));
        when(accounts.mfaStateOf("bff_iss")).thenReturn(Mono.empty());
        when(accountIssuers.issuerOf("google:a@x.com"))
                .thenReturn(Mono.just("https://casdoor-brandx.example.tld"));

        StepVerifier.create(controller.introspect("Bearer bff_iss"))
                .assertNext(r -> {
                    assertThat(r.issuer()).isEqualTo("https://casdoor-brandx.example.tld");
                    // The rest of the contract is untouched by the new field.
                    assertThat(r.id()).isEqualTo("google:a@x.com");
                    assertThat(r.status()).isEqualTo(AccountStatus.ACTIVE);
                })
                .verifyComplete();
    }

    @Test
    void introspect_legacyRowWithoutIssuer_returnsNullIssuer_restOfContractUnchanged() {
        // Legacy rows (pre-301, google/discord invite accounts, or a row whose stored issuer no
        // longer validates against the configured trusted set) surface issuer = null and EVERY
        // other field exactly as before — user-bff then degrades to its pre-301
        // singleTrustedIssuerOrNull behavior (fail-closed on a multi-brand cluster).
        Account a = acct(true);
        when(accounts.sessionOf("Bearer bff_legacy_iss")).thenReturn(Mono.just(a));
        when(suspensions.statusFor("a@x.com")).thenReturn(Mono.just(AccountStatus.active()));
        when(accounts.mfaStateOf("bff_legacy_iss")).thenReturn(Mono.empty());
        // setUp default: issuerOf -> Mono.empty() (the unset/untrusted read shape).

        StepVerifier.create(controller.introspect("Bearer bff_legacy_iss"))
                .assertNext(r -> {
                    assertThat(r.issuer()).isNull();
                    assertThat(r.casdoorSub()).isNull();
                    assertThat(r.id()).isEqualTo("google:a@x.com");
                    assertThat(r.provider()).isEqualTo("google");
                    assertThat(r.roles()).containsExactly("user");
                    assertThat(r.registrationComplete()).isTrue();
                    assertThat(r.status()).isEqualTo(AccountStatus.ACTIVE);
                    assertThat(r.mfaSatisfied()).isFalse();
                })
                .verifyComplete();
    }

    // ── /session/exchange suspension gate (closes the bff-exchange-bypasses-ban gap) ──

    @Test
    void exchange_bannedAccount_403_andCustodyNeverRead() {
        // A banned account behind the opaque session must be refused the custody swap, so the
        // gateway bff-exchange path cannot keep authorizing it on a still-valid custody JWT.
        when(accounts.sessionOfToken("bff_banned")).thenReturn(Mono.just(acct(true)));
        when(suspensions.statusFor("a@x.com"))
                .thenReturn(Mono.just(new AccountStatus(AccountStatus.BANNED, null, "banned")));
        StepVerifier.create(controller.exchange(new InternalAccountController.ExchangeRequest("bff_banned")))
                .verifyErrorSatisfies(e -> assertThat(((ResponseStatusException) e).getStatusCode())
                        .isEqualTo(HttpStatusCode.valueOf(403)));
        verify(accounts, never()).sessionRow(any());
    }

    @Test
    void exchange_suspendedAccount_403_andCustodyNeverRead() {
        when(accounts.sessionOfToken("bff_sus")).thenReturn(Mono.just(acct(true)));
        when(suspensions.statusFor("a@x.com"))
                .thenReturn(Mono.just(new AccountStatus(AccountStatus.SUSPENDED, null, "abuse")));
        StepVerifier.create(controller.exchange(new InternalAccountController.ExchangeRequest("bff_sus")))
                .verifyErrorSatisfies(e -> assertThat(((ResponseStatusException) e).getStatusCode())
                        .isEqualTo(HttpStatusCode.valueOf(403)));
        verify(accounts, never()).sessionRow(any());
    }

    @Test
    void exchange_activeAccount_proceedsToCustody() {
        // ACTIVE account → gate passes → custody served (the unchanged happy path).
        when(accounts.sessionOfToken("bff_ok")).thenReturn(Mono.just(acct(true)));
        when(suspensions.statusFor("a@x.com")).thenReturn(Mono.just(AccountStatus.active()));
        when(accounts.sessionRow("bff_ok"))
                .thenReturn(Mono.just(session("bff_ok", CIPHER.encrypt("JWT-A"), null,
                        LocalDateTime.now().plusHours(1))));
        StepVerifier.create(controller.exchange(new InternalAccountController.ExchangeRequest("bff_ok")))
                .assertNext(m -> assertThat(m.get("bearer")).isEqualTo("JWT-A"))
                .verifyComplete();
    }

    // ──────────────────────────── Usage recording (decision 55, #85) ──────────────────────

    @Test
    void recordUsage_forwardsAllThreeArgumentsVerbatim_toUsageServiceRecord() {
        // The straight pass-through contract: no re-derivation, no lookup — the exact
        // (handle, roles, action) triple the caller sent reaches UsageService.record().
        when(usage.record("bob@example.test", List.of("ROLE_USER"), "register"))
                .thenReturn(Mono.empty());

        StepVerifier.create(controller.recordUsage(new InternalAccountController.RecordUsageRequest(
                        "bob@example.test", List.of("ROLE_USER"), "register")))
                .verifyComplete();

        verify(usage).record("bob@example.test", List.of("ROLE_USER"), "register");
    }

    @Test
    void recordUsage_nullRoles_forwardedAsEmptyList_notNull() {
        // UsageService.record already null-safes roles internally, but the controller pins
        // this explicitly so a future UsageService change cannot silently start NPEing a
        // caller that (legitimately) knows no roles at record time.
        when(usage.record(eq("carol@example.test"), eq(List.of()), eq("login")))
                .thenReturn(Mono.empty());

        StepVerifier.create(controller.recordUsage(new InternalAccountController.RecordUsageRequest(
                        "carol@example.test", null, "login")))
                .verifyComplete();

        verify(usage).record("carol@example.test", List.of(), "login");
    }

    @Test
    void recordUsage_anyAction_notOnlyRegister_isForwarded() {
        // Decision 55's contract is UsageService.record's own three-argument shape, not a
        // register-only special case — any action user-bff (or a future internal caller)
        // wants recorded goes through unchanged.
        when(usage.record("dave@example.test", List.of("ROLE_ADMIN"), "matrix.entitled"))
                .thenReturn(Mono.empty());

        StepVerifier.create(controller.recordUsage(new InternalAccountController.RecordUsageRequest(
                        "dave@example.test", List.of("ROLE_ADMIN"), "matrix.entitled")))
                .verifyComplete();

        verify(usage).record("dave@example.test", List.of("ROLE_ADMIN"), "matrix.entitled");
    }

    @Test
    void recordUsage_neverTouchesAccountStore_noExistenceCheck() {
        // Deliberate: this endpoint trusts the caller and performs no AccountStore read,
        // matching AuthController's own emitAndSession/complete call sites (see the
        // controller's javadoc "No account lookup" section).
        when(usage.record(anyString(), any(), anyString())).thenReturn(Mono.empty());

        StepVerifier.create(controller.recordUsage(new InternalAccountController.RecordUsageRequest(
                        "erin@example.test", List.of(), "complete")))
                .verifyComplete();

        verify(accounts, never()).account(any());
        verify(accounts, never()).ensureAccount(any(), any());
    }
}
