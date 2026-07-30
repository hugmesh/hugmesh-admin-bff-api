package systems.hugmesh.adminbff.account;

import org.junit.jupiter.api.Test;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;
import systems.hugmesh.commons.security.DomainRegistry;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit coverage for {@link AccountIssuerService} — the SECURITY BOUNDARY of Liquibase
 * changeset 301 (the multi-brand bff_-session domain-scope fix).
 *
 * <p><b>Why this is a plain unit test, unlike {@code AccountCasdoorSubServiceTest}'s
 * Testcontainers shape.</b> The behaviour under test is the TRUST DECISION — which issuers
 * may be written at all — and that is pure logic over a {@link DomainRegistry} built from
 * config. It needs a REAL DomainRegistry (the actual parsing/normalisation is half the
 * contract) but only a MOCKED repository, since what matters is precisely whether a write
 * is attempted. Mocking the repo also makes the central assertion exact and unfakeable:
 * {@code verify(repo, never()).updateAccountIssuer(...)} — a forged issuer must reach the
 * database NEVER, which a row-readback test could only assert indirectly.
 *
 * <p>The single most important test here is {@link
 * #stamp_forgedIssuer_neverWritten_theCrossBrandForgeryGuard()}. {@code
 * InternalAccountController} decodes the id_token WITHOUT verifying its signature and the
 * token arrives in a user-bff-supplied request body, so the {@code iss} handed to {@link
 * AccountIssuerService#stamp} is attacker-controllable. An issuer decides TENANT SCOPE
 * (the gateway's DomainRegistry: "Never key the domain off a user-settable claim — a user
 * could forge cross-tenant scope"), so admitting an unvalidated one would be a cross-brand
 * read/write primitive — strictly worse than the fail-closed deny it replaces.
 */
class AccountIssuerServiceTest {

    private static final String BRAND_X = "https://casdoor-brandx.example.tld";
    private static final String BRAND_Y = "https://casdoor-brandy.example.tld";

    private final AccountIssuerRepository repo = mock(AccountIssuerRepository.class);

    /** A genuinely multi-brand registry — the deployment shape 301 exists to serve. */
    private static DomainRegistry multiBrand() {
        return new DomainRegistry("", BRAND_X + "=brandx," + BRAND_Y + "=brandy");
    }

    private AccountIssuerService serviceOn(DomainRegistry registry) {
        return new AccountIssuerService(repo, registry);
    }

    /** Stub the row-read the stamp fast-path performs. */
    private void existingRow(String accountId, String storedIssuer) {
        when(repo.findById(accountId)).thenReturn(Mono.just(new AccountIssuerRow(accountId, storedIssuer)));
        when(repo.updateAccountIssuer(anyString(), anyString())).thenReturn(Mono.just(1L));
    }

    // ── the happy path: a trusted issuer IS stamped ─────────────────────────────

    @Test
    void stamp_trustedIssuer_isWritten() {
        existingRow("acct-1", null);
        StepVerifier.create(serviceOn(multiBrand()).stamp("acct-1", BRAND_X)).verifyComplete();
        verify(repo).updateAccountIssuer("acct-1", BRAND_X);
    }

    @Test
    void stamp_trustedIssuer_withTrailingSlash_normalisesToTheRegistryKey() {
        // DomainRegistry strips a trailing slash from its configured keys, so a token whose
        // iss carries one must still match — and must persist the CANONICAL key form, or
        // user-bff's exact-match lookup would miss and fail closed on a legitimate login.
        existingRow("acct-slash", null);
        StepVerifier.create(serviceOn(multiBrand()).stamp("acct-slash", BRAND_X + "/")).verifyComplete();
        verify(repo).updateAccountIssuer("acct-slash", BRAND_X);
    }

    // ── *** THE SECURITY TEST *** ──────────────────────────────────────────────

    @Test
    void stamp_forgedIssuer_neverWritten_theCrossBrandForgeryGuard() {
        // The id_token is decoded but NOT signature-verified, and body.handle() is
        // user-bff-supplied — so this iss is attacker-chosen. It names no configured brand.
        // It must NEVER reach the column: a stamped forgery would let this account resolve a
        // brand scope it has no claim to (cross-tenant read/write), which is strictly worse
        // than the fail-closed deny that happens when the column stays null.
        when(repo.findById(anyString())).thenReturn(Mono.just(new AccountIssuerRow("acct-evil", null)));

        StepVerifier.create(serviceOn(multiBrand()).stamp("acct-evil", "https://evil.attacker.tld"))
                .verifyComplete();

        verify(repo, never()).updateAccountIssuer(anyString(), anyString());
    }

    @Test
    void stamp_forgedIssuer_neverOverwritesAnAlreadyVerifiedBrand() {
        // The takeover shape: an account legitimately bound to brandx logs in again with a
        // forged iss naming brandy (or anything else). The verified binding must survive
        // untouched — no overwrite, no clear.
        existingRow("acct-bound", BRAND_X);

        StepVerifier.create(serviceOn(multiBrand()).stamp("acct-bound", "https://evil.attacker.tld"))
                .verifyComplete();

        verify(repo, never()).updateAccountIssuer(anyString(), anyString());
    }

    @Test
    void stamp_emptyRegistry_neverWritten_theIsTrustedFailOpenGuard() {
        // THE SUBTLE ONE. DomainRegistry#isTrusted delegates to domainOf, which short-circuits
        // to DEFAULT_DOMAIN WITHOUT INSPECTING its argument when the registry map is empty —
        // i.e. isTrusted("https://evil.attacker.tld") returns TRUE in the no-config case. A
        // stamp gated on isTrusted would therefore persist an attacker-chosen issuer on every
        // unconfigured cluster: harmless the day it is written (domainOf ignores iss), then
        // silently authoritative the day someone turns app.tenancy.issuers on. The service
        // gates on strict membership of a NON-EMPTY trustedIssuers() set instead, so nothing
        // is ever written here.
        DomainRegistry unconfigured = new DomainRegistry("", "");
        assertThat(unconfigured.trustedIssuers()).isEmpty();
        assertThat(unconfigured.isTrusted("https://evil.attacker.tld"))
                .as("guard premise: isTrusted DOES fail open on an empty registry — "
                        + "that is exactly why stamp() must not use it")
                .isTrue();
        when(repo.findById(anyString())).thenReturn(Mono.just(new AccountIssuerRow("acct-noconf", null)));

        StepVerifier.create(serviceOn(unconfigured).stamp("acct-noconf", "https://evil.attacker.tld"))
                .verifyComplete();

        verify(repo, never()).updateAccountIssuer(anyString(), anyString());
    }

    @Test
    void stamp_singleIssuerRegistry_onlyThatIssuerIsAccepted() {
        // Single-issuer back-compat mode seeds exactly {thatIssuer -> "default"}: the real
        // issuer stamps, a forged one still does not.
        DomainRegistry single = new DomainRegistry(BRAND_X, "");
        existingRow("acct-single", null);

        StepVerifier.create(serviceOn(single).stamp("acct-single", BRAND_X)).verifyComplete();
        verify(repo).updateAccountIssuer("acct-single", BRAND_X);

        StepVerifier.create(serviceOn(single).stamp("acct-single", BRAND_Y)).verifyComplete();
        verify(repo, never()).updateAccountIssuer("acct-single", BRAND_Y);
    }

    // ── null-safety / no-op posture: never fail a login, never clear a binding ──

    @Test
    void stamp_nullOrBlankIssuer_isANoOp_andNeverClearsAVerifiedValue() {
        existingRow("acct-null", BRAND_X);
        AccountIssuerService svc = serviceOn(multiBrand());

        StepVerifier.create(svc.stamp("acct-null", null)).verifyComplete();
        StepVerifier.create(svc.stamp("acct-null", "")).verifyComplete();
        StepVerifier.create(svc.stamp("acct-null", "   ")).verifyComplete();

        verify(repo, never()).updateAccountIssuer(anyString(), anyString());
    }

    @Test
    void stamp_alreadyMatching_fastPathsToAPureRead_noWrite() {
        // The repeat-sign-in shape (ensureAccount re-runs on EVERY login): the common case
        // must not write.
        existingRow("acct-same", BRAND_X);
        StepVerifier.create(serviceOn(multiBrand()).stamp("acct-same", BRAND_X)).verifyComplete();
        verify(repo, never()).updateAccountIssuer(anyString(), anyString());
    }

    @Test
    void stamp_unknownAccountId_noOpsAtTheUpdate() {
        // No row yet → defaultIfEmpty synthesises a null-issuer row and the targeted UPDATE
        // simply affects 0 rows. Must not error (that would fail the login).
        when(repo.findById("ghost")).thenReturn(Mono.empty());
        when(repo.updateAccountIssuer(anyString(), anyString())).thenReturn(Mono.just(0L));

        StepVerifier.create(serviceOn(multiBrand()).stamp("ghost", BRAND_X)).verifyComplete();
        verify(repo).updateAccountIssuer("ghost", BRAND_X);
    }

    @Test
    void stamp_legacyRowWithNullColumn_isStampedOnNextTrustedLogin_selfHeal() {
        // The documented self-heal: a pre-301 row carries null and gets bound on its next
        // native login from a trusted issuer (ensureAccount re-runs every sign-in).
        existingRow("acct-legacy", null);
        StepVerifier.create(serviceOn(multiBrand()).stamp("acct-legacy", BRAND_Y)).verifyComplete();
        verify(repo).updateAccountIssuer("acct-legacy", BRAND_Y);
    }

    // ── read-side re-validation: config changes must not resurrect a stale brand ──

    @Test
    void issuerOf_trustedStoredValue_isReturned() {
        when(repo.findById("acct-r1")).thenReturn(Mono.just(new AccountIssuerRow("acct-r1", BRAND_X)));
        StepVerifier.create(serviceOn(multiBrand()).issuerOf("acct-r1"))
                .expectNext(BRAND_X)
                .verifyComplete();
    }

    @Test
    void issuerOf_storedValueNoLongerTrusted_readsAsUnset_failClosed() {
        // The trusted set is CONFIG and config changes do not rewrite already-stamped rows
        // (a brand decommissioned, app.tenancy.issuers rewritten). Surfacing a
        // no-longer-trusted issuer from a stale row would resurrect exactly the cross-brand
        // scope this changeset prevents, so the read re-validates and yields empty → the
        // response field is null → user-bff fails closed.
        DomainRegistry brandXOnly = new DomainRegistry("", BRAND_X + "=brandx");
        when(repo.findById("acct-r2")).thenReturn(Mono.just(new AccountIssuerRow("acct-r2", BRAND_Y)));

        StepVerifier.create(serviceOn(brandXOnly).issuerOf("acct-r2")).verifyComplete(); // empty
    }

    @Test
    void issuerOf_nullColumnOrMissingRow_readsAsUnset() {
        when(repo.findById("acct-r3")).thenReturn(Mono.just(new AccountIssuerRow("acct-r3", null)));
        when(repo.findById("acct-r4")).thenReturn(Mono.empty());
        AccountIssuerService svc = serviceOn(multiBrand());

        StepVerifier.create(svc.issuerOf("acct-r3")).verifyComplete(); // empty
        StepVerifier.create(svc.issuerOf("acct-r4")).verifyComplete(); // empty
    }

    // ── the trust gate itself, driven directly ─────────────────────────────────

    @Test
    void trustedIssuerOrNull_admitsOnlyConfiguredIssuers() {
        AccountIssuerService svc = serviceOn(multiBrand());

        assertThat(svc.trustedIssuerOrNull(BRAND_X)).isEqualTo(BRAND_X);
        assertThat(svc.trustedIssuerOrNull(BRAND_Y)).isEqualTo(BRAND_Y);
        assertThat(svc.trustedIssuerOrNull(BRAND_X + "/")).isEqualTo(BRAND_X);
        assertThat(svc.trustedIssuerOrNull("  " + BRAND_X + "  ")).isEqualTo(BRAND_X);

        // Everything else is untrusted → null → no stamp → fail closed.
        assertThat(svc.trustedIssuerOrNull(null)).isNull();
        assertThat(svc.trustedIssuerOrNull("")).isNull();
        assertThat(svc.trustedIssuerOrNull("https://evil.attacker.tld")).isNull();
        // Near-miss forgeries: prefix/suffix/substring games must not match.
        assertThat(svc.trustedIssuerOrNull(BRAND_X + ".evil.tld")).isNull();
        assertThat(svc.trustedIssuerOrNull("https://evil.tld/" + BRAND_X)).isNull();
        assertThat(svc.trustedIssuerOrNull("casdoor-brandx.example.tld")).isNull();
        assertThat(svc.trustedIssuerOrNull("HTTPS://CASDOOR-BRANDX.EXAMPLE.TLD")).isNull();
    }
}
