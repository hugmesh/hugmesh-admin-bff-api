package systems.hugmesh.adminbff.desktop;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Nested;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.data.r2dbc.test.autoconfigure.DataR2dbcTest;
import org.springframework.context.annotation.Import;
import org.springframework.r2dbc.core.DatabaseClient;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.test.context.ActiveProfiles;
import reactor.test.StepVerifier;
import systems.hugmesh.commons.security.DomainRegistry;
import systems.hugmesh.commons.security.PrincipalDomain;
import systems.hugmesh.adminbff.support.TestDatabaseConfig;

import java.time.Instant;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The desktop_app_catalog R2DBC repository over a Liquibase-applied H2 (PG-compat) — proves
 * the 140 changelog applies (table + source CHECK + UNIQUE) and the curation + the REAL
 * discover-registry filtering round-trip.
 *
 * <p>Per the test-standard: USER-SITUATIONAL (add default-disabled), MULTIUSER (enable/disable
 * flips visibility), CROSS-USER (the domain-lock — a brand-X scoped read never sees brand-Y;
 * the enabled-only filter), CONCURRENT (the UNIQUE per (domain, app_ref) rejects a duplicate).
 */
@DataR2dbcTest
@Import(TestDatabaseConfig.class)
@ActiveProfiles("test")
class DesktopAppCatalogRepositoryTest {

    @Autowired DatabaseClient db;

    @BeforeEach
    void clear() {
        db.sql("DELETE FROM desktop_app_catalog").fetch().rowsUpdated().block();
    }

    private DesktopAppCatalogRepository repo() {
        return new DesktopAppCatalogRepository(systems.hugmesh.adminbff.testutil.R2dbcRepos.of(db, systems.hugmesh.adminbff.desktop.DesktopAppCatalogR2dbcRepository.class));
    }

    private static final DomainRegistry REGISTRY = new DomainRegistry("",
            "https://idp.brandx.example=brandx,https://idp.brandy.example=brandy");

    private static PrincipalDomain admin(String issuer) {
        Jwt jwt = Jwt.withTokenValue("t").header("alg", "none")
                .issuedAt(Instant.now()).expiresAt(Instant.now().plusSeconds(3600))
                .subject("u").issuer(issuer).claim("roles", List.of("admin")).build();
        Authentication auth = new JwtAuthenticationToken(jwt,
                List.of(new SimpleGrantedAuthority("ROLE_USER"), new SimpleGrantedAuthority("ROLE_ADMIN")));
        return PrincipalDomain.of(auth, REGISTRY);
    }

    private static PrincipalDomain superadmin() {
        Jwt jwt = Jwt.withTokenValue("t").header("alg", "none")
                .issuedAt(Instant.now()).expiresAt(Instant.now().plusSeconds(3600))
                .subject("u").issuer("https://idp.brandx.example").claim("roles", List.of("superadmin")).build();
        Authentication auth = new JwtAuthenticationToken(jwt,
                List.of(new SimpleGrantedAuthority("ROLE_USER"), new SimpleGrantedAuthority("ROLE_SUPERADMIN")));
        return PrincipalDomain.of(auth, REGISTRY);
    }

    // ── USER-SITUATIONAL: add is default-disabled (default-NONE) ─────────────────

    @Nested
    class AddDefaultNone {
        @Test
        void insert_roundTrips_disabledByDefault() {
            DesktopAppCatalogEntry e = repo().insert("brandx", "org.mozilla.firefox", "Firefox",
                    "FLATPAK", "alice").block();
            assertThat(e).isNotNull();
            assertThat(e.enabled()).isFalse();           // add != enable
            assertThat(e.domain()).isEqualTo("brandx");
        }

        @Test
        void disabledRef_isNotServedByRegistry() {
            DesktopAppCatalogRepository r = repo();
            r.insert("brandx", "org.x.app", "X", "FLATPAK", "alice").block();   // disabled
            // the registry filter (enabled-only) serves NOTHING for a disabled-only catalog.
            assertThat(r.listEnabledForDomain("brandx").collectList().block()).isEmpty();
            StepVerifier.create(r.findEnabledByRef("brandx", "org.x.app")).verifyComplete();
        }
    }

    // ── MULTIUSER-SITUATIONAL: enable/disable flips visibility ───────────────────

    @Nested
    class EnableFlipsVisibility {
        @Test
        void enable_thenServed_disable_thenNot() {
            DesktopAppCatalogRepository r = repo();
            DesktopAppCatalogEntry e = r.insert("brandx", "org.x.app", "X", "FLATPAK", "a").block();
            assertThat(r.setEnabled(e.id(), true, superadmin()).block()).isEqualTo(1L);
            assertThat(r.listEnabledForDomain("brandx").collectList().block())
                    .extracting(DesktopAppCatalogEntry::appRef).containsExactly("org.x.app");
            assertThat(r.setEnabled(e.id(), false, superadmin()).block()).isEqualTo(1L);
            assertThat(r.listEnabledForDomain("brandx").collectList().block()).isEmpty();
        }
    }

    // ── CROSS-USER / domain isolation (the discover-registry keystone) ───────────

    @Nested
    class DomainIsolation {
        @Test
        void registryFilter_isDomainLocked_noCrossDomainLeak() {
            DesktopAppCatalogRepository r = repo();
            DesktopAppCatalogEntry y = r.insert("brandy", "com.brandy.app", "BY", "FLATPAK", "a").block();
            r.setEnabled(y.id(), true, superadmin()).block();   // enabled in brandY
            // brand-X's registry view never sees brandY's enabled ref (no cross-domain leak).
            assertThat(r.listEnabledForDomain("brandx").collectList().block()).isEmpty();
            StepVerifier.create(r.findEnabledByRef("brandx", "com.brandy.app")).verifyComplete();
            // brandY does see it.
            assertThat(r.listEnabledForDomain("brandy").collectList().block())
                    .extracting(DesktopAppCatalogEntry::appRef).containsExactly("com.brandy.app");
        }

        @Test
        void scopedAdminRead_seesOnlyOwnBrand_superadminSeesAll() {
            DesktopAppCatalogRepository r = repo();
            r.insert("brandx", "a.x", "X", "FLATPAK", "a").block();
            r.insert("brandy", "a.y", "Y", "FLATPAK", "a").block();
            assertThat(r.list(admin("https://idp.brandx.example")).collectList().block())
                    .extracting(DesktopAppCatalogEntry::domain).containsOnly("brandx");
            assertThat(r.list(superadmin()).collectList().block())
                    .extracting(DesktopAppCatalogEntry::domain).contains("brandx", "brandy");
        }

        @Test
        void scopedAdmin_cannotMutateOtherBrandRow() {
            DesktopAppCatalogRepository r = repo();
            DesktopAppCatalogEntry y = r.insert("brandy", "a.y", "Y", "FLATPAK", "a").block();
            // a brand-X scoped admin cannot enable / delete a brand-Y row (rows-updated 0).
            assertThat(r.setEnabled(y.id(), true, admin("https://idp.brandx.example")).block()).isEqualTo(0L);
            assertThat(r.delete(y.id(), admin("https://idp.brandx.example")).block()).isEqualTo(0L);
            // and brandY's superadmin still sees it untouched (still disabled).
            assertThat(r.findById(y.id(), superadmin()).block().enabled()).isFalse();
        }
    }

    // ── CONCURRENT / conflicting: UNIQUE per (domain, app_ref) ───────────────────

    @Nested
    class UniquePerDomainRef {
        @Test
        void duplicateRefSameDomain_isRejected_byUnique() {
            DesktopAppCatalogRepository r = repo();
            r.insert("brandx", "dup.ref", "One", "FLATPAK", "a").block();
            // a second insert of the SAME (domain, app_ref) violates uq_desktop_app_catalog_domain_ref.
            StepVerifier.create(r.insert("brandx", "dup.ref", "Two", "FLATPAK", "a"))
                    .expectError().verify();
            // the same ref in ANOTHER domain is fine (per-domain uniqueness).
            assertThat(r.insert("brandy", "dup.ref", "Y", "FLATPAK", "a").block()).isNotNull();
        }
    }
}
