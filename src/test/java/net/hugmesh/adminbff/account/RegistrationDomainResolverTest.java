package net.hugmesh.adminbff.account;

import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import net.hugmesh.authcore.account.AccountStore;
import net.hugmesh.commons.security.DomainRegistry;
import net.hugmesh.commons.security.PrincipalDomain;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The pre-auth domain source for the registration gate (hugmesh-auth-core issue #1).
 *
 * <p>These assertions are the reason the gate can be scoped at all: {@code
 * POST /bff/register/**} has no validated {@code PrincipalDomain}, so this class decides the
 * brand, and it must do so from SERVER-TRUSTED inputs only — a caller-chosen domain would
 * re-open the very cross-brand hole the fix closes. The four resolution steps are each
 * pinned here, including the fail-closed multi-brand case.
 */
class RegistrationDomainResolverTest {

    private static final String BRAND_A_ISSUER = "https://id.brand-a.test";
    private static final String BRAND_B_ISSUER = "https://id.brand-b.test";
    private static final String TWO_BRANDS =
            BRAND_A_ISSUER + "=brand-a," + BRAND_B_ISSUER + "=brand-b";

    private static RegistrationDomainResolver resolver(String issuerUri, String issuersCsv, String pin) {
        return new RegistrationDomainResolver(new DomainRegistry(issuerUri, issuersCsv), pin);
    }

    private static Authentication jwtFrom(String issuer) {
        Jwt jwt = Jwt.withTokenValue("token")
                .header("alg", "none")
                .issuer(issuer)
                .claim("sub", "someone")
                .build();
        return new JwtAuthenticationToken(jwt);
    }

    // ── 1. the forwarded token's issuer ────────────────────────────────
    @Test
    void trustedIssuer_resolvesThatBrand_notTheOther() {
        RegistrationDomainResolver r = resolver("", TWO_BRANDS, "");
        assertThat(r.forRegistration(jwtFrom(BRAND_A_ISSUER))).isEqualTo("brand-a");
        assertThat(r.forRegistration(jwtFrom(BRAND_B_ISSUER))).isEqualTo("brand-b");
    }

    @Test
    void trustedIssuer_trailingSlashStillMatches() {
        RegistrationDomainResolver r = resolver("", TWO_BRANDS, "");
        assertThat(r.forRegistration(jwtFrom(BRAND_A_ISSUER + "/"))).isEqualTo("brand-a");
    }

    @Test
    void untrustedIssuer_neverBorrowsAnotherBrand_failsClosed() {
        // A token from an issuer this deployment does not list must not resolve to ANY brand.
        RegistrationDomainResolver r = resolver("", TWO_BRANDS, "");
        assertThat(r.forRegistration(jwtFrom("https://id.evil.test")))
                .isEqualTo(PrincipalDomain.NO_DOMAIN);
    }

    @Test
    void issuerIsIgnoredWhenNoTrustedSetIsConfigured() {
        // DomainRegistry.domainOf answers "default" for ANY string on an empty registry, so a
        // forged iss must never be consulted. Strict membership of a NON-EMPTY set only.
        RegistrationDomainResolver r = resolver("", "", "");
        assertThat(r.forRegistration(jwtFrom("https://id.evil.test")))
                .isEqualTo(AccountStore.DEFAULT_DOMAIN);
    }

    @Test
    void nonJwtAuthentication_fallsBack_neverThrows() {
        RegistrationDomainResolver r = resolver("", "", "");
        assertThat(r.forRegistration(new TestingAuthenticationToken("bob", "creds")))
                .isEqualTo(AccountStore.DEFAULT_DOMAIN);
    }

    // ── 2. the per-deployment pin ──────────────────────────────────────
    @Test
    void pin_isUsedWhenNoTokenNamesABrand() {
        RegistrationDomainResolver r = resolver("", TWO_BRANDS, "brand-b");
        assertThat(r.forRegistration(null)).isEqualTo("brand-b");
    }

    @Test
    void pin_winsOverAForwardedToken_soTheCallerCannotPickTheBrand() {
        // A validated token proves WHO the caller is, not WHICH brand this deployment
        // registers for — and attaching one is the caller's choice. If the token won, an
        // attacker holding a valid brand-A token could POST /bff/register to this brand-B
        // instance, satisfy the gate from brand-A's allowlist and be minted a brand-B
        // session: the cross-brand hole this class exists to close, re-opened by adding a
        // header. The pin is the operator's word and is the one input a caller cannot pick.
        RegistrationDomainResolver r = resolver("", TWO_BRANDS, "brand-b");
        assertThat(r.forRegistration(jwtFrom(BRAND_A_ISSUER))).isEqualTo("brand-b");
        assertThat(r.forRegistration(jwtFrom(BRAND_B_ISSUER))).isEqualTo("brand-b");
    }

    @Test
    void unpinned_aTrustedTokenStillNamesTheBrand() {
        // Without a pin the token is the only server-trusted signal there is, so it still
        // decides — this is the multi-brand admin-bff the resolver's step 2 serves.
        RegistrationDomainResolver r = resolver("", TWO_BRANDS, "");
        assertThat(r.forRegistration(jwtFrom(BRAND_A_ISSUER))).isEqualTo("brand-a");
    }

    @Test
    void pin_isTrimmed() {
        assertThat(resolver("", TWO_BRANDS, "  brand-a  ").forRegistration(null)).isEqualTo("brand-a");
    }

    // ── 3. the deployment's only brand (single-tenant back-compat) ─────
    @Test
    void noTenancyConfigAtAll_isTheLegacyDefaultDomain() {
        // The single-tenant install: seedAdmins stamps DEFAULT_DOMAIN and the changeset-220
        // back-fill wrote it onto every pre-existing row, so this keeps that install
        // byte-identical to the unscoped gate it replaces.
        assertThat(resolver("", "", "").fallback()).isEqualTo(AccountStore.DEFAULT_DOMAIN);
    }

    @Test
    void singleIssuerBackCompat_isAlsoTheDefaultDomain() {
        assertThat(resolver("https://id.hugmesh.test", "", "").fallback())
                .isEqualTo(AccountStore.DEFAULT_DOMAIN);
    }

    @Test
    void exactlyOneConfiguredBrand_isThatBrand() {
        assertThat(resolver("", BRAND_A_ISSUER + "=brand-a", "").fallback()).isEqualTo("brand-a");
    }

    @Test
    void oneNamedBrand_isNotTheDefaultDomain_whichIsWhyTheAdminSeedMustBeMirrored() {
        // The trap RegistrationDomainAdminSeed exists for: naming ONE brand in
        // app.tenancy.issuers is a supported single-brand shape, but it does NOT leave the
        // gate reading "default". auth-core's AccountStore.seedAdmins() hardcodes
        // DEFAULT_DOMAIN, so without the mirror the bootstrap admin's row is invisible here.
        assertThat(resolver("", BRAND_A_ISSUER + "=brand-a", "").fallback())
                .isNotEqualTo(AccountStore.DEFAULT_DOMAIN);
        assertThat(resolver("", "", "brand-a").fallback()).isNotEqualTo(AccountStore.DEFAULT_DOMAIN);
    }

    // ── 4. fail closed ─────────────────────────────────────────────────
    @Test
    void twoBrandsAndNothingNamesOne_failsClosed_neverGuessesDefault() {
        // Guessing "default" here would admit anyone the mesh-default allowlist holds, and
        // would be indistinguishable from a correct answer in the logs.
        assertThat(resolver("", TWO_BRANDS, "").fallback()).isEqualTo(PrincipalDomain.NO_DOMAIN);
        assertThat(PrincipalDomain.NO_DOMAIN).isNotEqualTo(AccountStore.DEFAULT_DOMAIN);
    }

    // ── the internal (trusted-caller) surface ──────────────────────────
    @Test
    void internalCaller_mayNameTheBrand() {
        RegistrationDomainResolver r = resolver("", TWO_BRANDS, "");
        assertThat(r.forInternalCaller("brand-a")).isEqualTo("brand-a");
        assertThat(r.forInternalCaller(" brand-b ")).isEqualTo("brand-b");
    }

    @Test
    void internalCaller_omittedOrBlank_fallsBack() {
        RegistrationDomainResolver r = resolver("", "", "");
        assertThat(r.forInternalCaller(null)).isEqualTo(AccountStore.DEFAULT_DOMAIN);
        assertThat(r.forInternalCaller("   ")).isEqualTo(AccountStore.DEFAULT_DOMAIN);
    }

    // ── issue #47: a supplied brand is honoured ONLY when this deployment serves it ──
    @Test
    void internalCaller_unknownBrand_failsClosed_neverDegradesToFallback() {
        // The holder of the internal credential names a brand this mesh does not serve. Before
        // #47 the value passed through verbatim into the repository predicate; degrading to
        // fallback() instead would hide the caller bug AND (on a single-brand mesh) answer with
        // the deployment's own brand. Neither: the sentinel matches no allowlist row.
        RegistrationDomainResolver two = resolver("", TWO_BRANDS, "");
        assertThat(two.forInternalCaller("brand-x")).isEqualTo(PrincipalDomain.NO_DOMAIN);

        RegistrationDomainResolver one = resolver("", BRAND_A_ISSUER + "=brand-a", "");
        assertThat(one.fallback()).isEqualTo("brand-a");
        assertThat(one.forInternalCaller("brand-x")).isEqualTo(PrincipalDomain.NO_DOMAIN);

        RegistrationDomainResolver legacy = resolver("", "", "");
        assertThat(legacy.fallback()).isEqualTo(AccountStore.DEFAULT_DOMAIN);
        assertThat(legacy.forInternalCaller("brand-x")).isEqualTo(PrincipalDomain.NO_DOMAIN);
    }

    @Test
    void internalCaller_defaultBrand_isAcceptedOnlyWhereItIsTheDeploymentsOwnAnswer() {
        // DomainRegistry.isKnownDomain("default") is deliberately FALSE (a back-compat
        // sentinel, not a per-brand Casdoor). But on the legacy single-tenant install and in
        // issuer-uri-only mode "default" IS the one brand the rows carry — the same answer
        // fallback() gives — so naming it must not be refused there...
        assertThat(resolver("", "", "").forInternalCaller("default"))
                .isEqualTo(AccountStore.DEFAULT_DOMAIN);
        assertThat(resolver("https://id.hugmesh.test", "", "").forInternalCaller("default"))
                .isEqualTo(AccountStore.DEFAULT_DOMAIN);
        // ...while on a multi-brand mesh, or one that names a single non-default brand,
        // "default" is NOT a brand this deployment serves and fails closed.
        assertThat(resolver("", TWO_BRANDS, "").forInternalCaller("default"))
                .isEqualTo(PrincipalDomain.NO_DOMAIN);
        assertThat(resolver("", BRAND_A_ISSUER + "=brand-a", "").forInternalCaller("default"))
                .isEqualTo(PrincipalDomain.NO_DOMAIN);
    }

    @Test
    void internalCaller_pinnedBrand_isAccepted_evenWhenNotInTheRegistry() {
        // The pin is the operator's own statement of which brand this admin-bff serves, so a
        // caller naming it is naming the deployment's brand — accepted whether or not the
        // registry lists it (an unconfigured registry + a pin is a supported shape).
        assertThat(resolver("", "", "brand-b").forInternalCaller("brand-b")).isEqualTo("brand-b");
        RegistrationDomainResolver pinnedTwo = resolver("", TWO_BRANDS, "brand-b");
        assertThat(pinnedTwo.forInternalCaller("brand-b")).isEqualTo("brand-b"); // the pin
        assertThat(pinnedTwo.forInternalCaller("brand-a")).isEqualTo("brand-a"); // still known
        assertThat(pinnedTwo.forInternalCaller("brand-z")).isEqualTo(PrincipalDomain.NO_DOMAIN);
    }

    @Test
    void internalCaller_valueIsComparedExactly_neverNormalisedIntoAMatch() {
        // Registry names are [a-z0-9-]-sanitized; a differently-cased or decorated spelling can
        // match no row, and must be refused rather than "helpfully" lower-cased into a brand.
        RegistrationDomainResolver r = resolver("", TWO_BRANDS, "");
        assertThat(r.forInternalCaller("Brand-A")).isEqualTo(PrincipalDomain.NO_DOMAIN);
        assertThat(r.forInternalCaller("brand-a'; --")).isEqualTo(PrincipalDomain.NO_DOMAIN);
        assertThat(r.forInternalCaller(PrincipalDomain.NO_DOMAIN)).isEqualTo(PrincipalDomain.NO_DOMAIN);
    }
}
