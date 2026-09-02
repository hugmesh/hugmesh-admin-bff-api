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
    void pin_doesNotOverrideATrustedToken() {
        // The token is the stronger evidence: it is cryptographically validated per-request,
        // the pin is a deployment-wide default for requests that carry none.
        RegistrationDomainResolver r = resolver("", TWO_BRANDS, "brand-b");
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
}
