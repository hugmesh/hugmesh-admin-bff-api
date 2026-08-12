package net.hugmesh.adminbff.config;

import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import reactor.core.publisher.Flux;
import net.hugmesh.commons.security.CasdoorAuthorities;
import net.hugmesh.commons.security.DomainRegistry;

import java.time.Instant;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit test for the Casdoor JWT → authority converter (logic copied from
 * hugmesh-gateway's adversarially-verified-safe CasdoorAuthorities): ROLE_USER
 * floor; roles (string or {name}) → ROLE_&lt;UPPER&gt;; permissions verbatim EXCEPT
 * reserved-prefix entries STRIPPED; isAdmin → ROLE_ADMIN; exactly one issuer-derived
 * DOMAIN_&lt;x&gt;.
 *
 * <p>Delineated per the test standard:
 * <ul>
 *   <li>USER-SITUATIONAL — a single token's own authority mapping.</li>
 *   <li>CROSS-USER — the authority-INJECTION regressions (a brand-X token MUST NOT
 *       forge a DOMAIN_ tenant scope or a ROLE_SUPERADMIN super-role through the
 *       user-influenced permissions claim).</li>
 * </ul>
 */
class SecurityConfigConverterTest {

    private static Jwt.Builder base() {
        return Jwt.withTokenValue("t").header("alg", "none")
                .issuedAt(Instant.now()).expiresAt(Instant.now().plusSeconds(3600))
                .subject("u");
    }

    private static List<String> authorities(Jwt jwt) {
        return SecurityConfig.casdoorAuthoritiesConverter()
                .convert(jwt)
                .map(GrantedAuthority::getAuthority)
                .collectList()
                .block();
    }

    private static List<String> authorities(Jwt jwt, DomainRegistry registry) {
        return SecurityConfig.casdoorAuthoritiesConverter(registry)
                .convert(jwt)
                .map(GrantedAuthority::getAuthority)
                .collectList()
                .block();
    }

    @Nested
    class UserSituational {

        @Test
        void floorIsRoleUserPlusDefaultDomain() {
            // Single-issuer / no config => DOMAIN_default floor, ROLE_USER floor.
            assertThat(authorities(base().build()))
                    .containsExactlyInAnyOrder("ROLE_USER", "DOMAIN_default");
        }

        @Test
        void stringRolesBecomeRolePrefixedUppercase() {
            Jwt jwt = base().claim("roles", List.of("admin", "mod")).build();
            assertThat(authorities(jwt)).contains("ROLE_USER", "ROLE_ADMIN", "ROLE_MOD");
        }

        @Test
        void objectRolesWithNameAreMapped() {
            Jwt jwt = base().claim("roles", List.of(Map.of("name", "admin"))).build();
            assertThat(authorities(jwt)).contains("ROLE_ADMIN");
        }

        @Test
        void permissionsArePassedThroughVerbatim() {
            Jwt jwt = base().claim("permissions", List.of("urn:games:play")).build();
            assertThat(authorities(jwt)).contains("urn:games:play");
        }

        @Test
        void isAdminTrueAddsRoleAdmin() {
            Jwt jwt = base().claim("isAdmin", true).build();
            assertThat(authorities(jwt)).contains("ROLE_ADMIN");
        }

        @Test
        void exactlyOneDomainAuthorityIsStamped() {
            List<String> auth = authorities(base().build());
            assertThat(auth.stream().filter(a -> a.startsWith("DOMAIN_"))).hasSize(1);
        }

        @Test
        void converterReturnsFlux() {
            Flux<GrantedAuthority> flux = SecurityConfig.casdoorAuthoritiesConverter().convert(base().build());
            assertThat(flux.collectList().block()).isNotEmpty();
        }

        @Test
        void issuerDerivesDomainViaRegistry() {
            // Multi-issuer registry: brand-x issuer => DOMAIN_brandx (issuer-keyed, not
            // user-settable).
            DomainRegistry registry = new DomainRegistry("",
                    "https://idp.brandx.example=brandx,https://idp.brandy.example=brandy");
            Jwt jwt = base().issuer("https://idp.brandx.example").build();
            assertThat(authorities(jwt, registry)).contains("DOMAIN_brandx").doesNotContain("DOMAIN_brandy");
        }
    }

    // ── D8 MFA_SATISFIED marker (converter-parity copy of the gateway change) ──
    private static final long NOW = 1_750_000_000_000L;
    private static final long WINDOW = 600_000L; // 10m

    private static final DomainRegistry SINGLE = new DomainRegistry("", "");

    private static List<String> mfaAuthorities(Jwt jwt, boolean enabled, long now) {
        return CasdoorAuthorities
                .authorities(jwt, SINGLE, new CasdoorAuthorities.MfaConfig(enabled, WINDOW), now)
                .stream().map(GrantedAuthority::getAuthority).toList();
    }

    private static Jwt mfaJwt(String satisfiedAt) {
        return base().claim("mfa_satisfied_at", satisfiedAt).build();
    }

    @Nested
    class MfaMarkerDerivation {

        @Test
        void disabled_neverProducesMarker_byteIdenticalLegacy() {
            // Dark default: even a perfectly fresh stamp yields the legacy authority set.
            List<String> auth = mfaAuthorities(mfaJwt(Long.toString(NOW)), false, NOW);
            assertThat(auth).containsExactlyInAnyOrder("ROLE_USER", "DOMAIN_default");
            // And the MfaConfig.DISABLED path matches the legacy authorities() overload exactly.
            List<String> legacy = CasdoorAuthorities.authorities(mfaJwt(Long.toString(NOW)), SINGLE)
                    .stream().map(GrantedAuthority::getAuthority).toList();
            assertThat(legacy).isEqualTo(auth);
        }

        @Test
        void enabled_freshStringStamp_addsMarker() {
            assertThat(mfaAuthorities(mfaJwt(Long.toString(NOW - 60_000L)), true, NOW))
                    .contains("MFA_SATISFIED");
            // Boundary: exactly at the window edge is still fresh.
            assertThat(mfaAuthorities(mfaJwt(Long.toString(NOW - WINDOW)), true, NOW))
                    .contains("MFA_SATISFIED");
        }

        @Test
        void enabled_staleStamp_failsClosed() {
            assertThat(mfaAuthorities(mfaJwt(Long.toString(NOW - WINDOW - 1)), true, NOW))
                    .doesNotContain("MFA_SATISFIED");
        }

        @Test
        void enabled_futureStamp_rejected() {
            assertThat(mfaAuthorities(mfaJwt(Long.toString(NOW + 1)), true, NOW))
                    .doesNotContain("MFA_SATISFIED");
        }

        @Test
        void enabled_missingOrMalformed_failsClosed() {
            assertThat(mfaAuthorities(base().build(), true, NOW)).doesNotContain("MFA_SATISFIED");
            assertThat(mfaAuthorities(mfaJwt("   "), true, NOW)).doesNotContain("MFA_SATISFIED");
            assertThat(mfaAuthorities(mfaJwt("not-a-number"), true, NOW)).doesNotContain("MFA_SATISFIED");
            assertThat(mfaAuthorities(mfaJwt("0"), true, NOW)).doesNotContain("MFA_SATISFIED");
            assertThat(mfaAuthorities(mfaJwt("-1"), true, NOW)).doesNotContain("MFA_SATISFIED");
        }

        @Test
        void marker_isNonRole_neverSatisfiesHasRole() {
            // MFA_SATISFIED carries NO ROLE_ prefix, so it can never accidentally satisfy
            // a hasRole()/route-access role check.
            List<String> auth = mfaAuthorities(mfaJwt(Long.toString(NOW)), true, NOW);
            assertThat(auth).contains("MFA_SATISFIED").doesNotContain("ROLE_MFA_SATISFIED");
        }

        @Test
        void forgedPermissionsMfaSatisfied_isDropped_evenWhenEnabled() {
            // A token with NO real stamp but a forged permissions:["MFA_SATISFIED"] must NOT
            // gain the marker — the reserved-prefix guard strips it; the only source is the
            // validated mfa_satisfied_at claim (absent here).
            Jwt jwt = base().claim("permissions", List.of("MFA_SATISFIED")).build();
            assertThat(mfaAuthorities(jwt, true, NOW)).doesNotContain("MFA_SATISFIED");
            // Mixed-case forgery is also stripped (trim+upper guard).
            Jwt mixed = base().claim("permissions", List.of("mfa_satisfied")).build();
            assertThat(mfaAuthorities(mixed, true, NOW)).doesNotContain("MFA_SATISFIED", "mfa_satisfied");
        }
    }

    @Nested
    class CrossUserInjectionRegressions {

        @Test
        void permissionsCannotForgeDomainTenantScope() {
            // A brand-X token carrying permissions:["DOMAIN_brandy"] MUST NOT mint a
            // forged tenant scope — the reserved-prefix guard strips it; the genuine
            // issuer-derived DOMAIN_ (here DOMAIN_default) is the only DOMAIN_.
            Jwt jwt = base().claim("permissions", List.of("DOMAIN_brandy")).build();
            List<String> auth = authorities(jwt);
            assertThat(auth).doesNotContain("DOMAIN_brandy");
            assertThat(auth.stream().filter(a -> a.startsWith("DOMAIN_"))).containsExactly("DOMAIN_default");
        }

        @Test
        void permissionsCannotForgeSuperadminRole() {
            // permissions:["ROLE_SUPERADMIN"] MUST be dropped — ROLE_ authorities come
            // ONLY from the roles claim / isAdmin, never a verbatim permission string.
            Jwt jwt = base().claim("permissions", List.of("ROLE_SUPERADMIN")).build();
            assertThat(authorities(jwt)).doesNotContain("ROLE_SUPERADMIN");
        }

        @Test
        void rolesEntryNamedDomainBecomesInertRolePrefixed() {
            // A roles entry "DOMAIN_x" gains the ROLE_ prefix first → ROLE_DOMAIN_X
            // (inert, non-tenant), never a DOMAIN_ tenant authority.
            Jwt jwt = base().claim("roles", List.of("DOMAIN_x")).build();
            List<String> auth = authorities(jwt);
            assertThat(auth).contains("ROLE_DOMAIN_X");
            assertThat(auth.stream().filter(a -> a.startsWith("DOMAIN_"))).containsExactly("DOMAIN_default");
        }

        @Test
        void caseInsensitiveReservedPrefixIsStripped() {
            // Lower/mixed-case reserved prefixes are also stripped (the guard
            // upper-cases before comparing).
            Jwt jwt = base().claim("permissions", List.of("domain_brandy", "Role_Admin")).build();
            List<String> auth = authorities(jwt);
            assertThat(auth).doesNotContain("domain_brandy", "Role_Admin");
        }
    }
}
