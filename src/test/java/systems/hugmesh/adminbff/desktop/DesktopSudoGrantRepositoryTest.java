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
 * The desktop_sudo_grant R2DBC repository over a Liquibase-applied H2 (PG-compat) — proves
 * the 141 changelog applies (table + CHECKs + FK) and the device_ssh_license-cloned idiom
 * round-trips.
 *
 * <p>A {@code device_registry} parent row is seeded for the FK. Per the test-standard:
 * USER-SITUATIONAL (grant/entitlement), MULTIUSER (revoke removes the entitlement),
 * CROSS-USER (scoped revoke can't touch another brand), CONCURRENT (CAS revoke single-winner).
 */
@DataR2dbcTest
@Import(TestDatabaseConfig.class)
@ActiveProfiles("test")
class DesktopSudoGrantRepositoryTest {

    @Autowired DatabaseClient db;

    private static final String DEV_X = "dev-x-1";
    private static final String DEV_Y = "dev-y-1";

    @BeforeEach
    void seed() {
        // child tables FK -> device_registry; delete them first (the context may be cached
        // + shared across the desktop @DataR2dbcTest classes that share this config).
        db.sql("DELETE FROM desktop_sudo_grant").fetch().rowsUpdated().block();
        db.sql("DELETE FROM desktop_install_request").fetch().rowsUpdated().block();
        db.sql("DELETE FROM device_ssh_license").fetch().rowsUpdated().block();
        db.sql("DELETE FROM device_registry").fetch().rowsUpdated().block();
        insertDevice(DEV_X, "fp-x", "brandx");
        insertDevice(DEV_Y, "fp-y", "brandy");
    }

    private void insertDevice(String id, String fp, String domain) {
        db.sql("INSERT INTO device_registry "
                        + "(id, machine_key_fp, hostname, image_type, owner_type, physical_owner, domain, mesh_id) "
                        + "VALUES (:id, :fp, :h, 'client', 'ADMIN', 'o', :domain, 'mesh-1')")
                .bind("id", id).bind("fp", fp).bind("h", id).bind("domain", domain)
                .fetch().rowsUpdated().block();
    }

    private DesktopSudoGrantRepository repo() {
        return new DesktopSudoGrantRepository(systems.hugmesh.adminbff.testutil.R2dbcRepos.of(db, systems.hugmesh.adminbff.desktop.DesktopSudoGrantR2dbcRepository.class));
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

    // ── USER-SITUATIONAL: grant -> active entitlement ────────────────────────────

    @Nested
    class GrantEntitlement {
        @Test
        void insertActive_roundTrips_andEntitlementResolves() {
            DesktopSudoGrant g = repo().insertActive("alice", DEV_X, "brandx", "root", 1L).block();
            assertThat(g.isActive()).isTrue();
            assertThat(g.domain()).isEqualTo("brandx");
            assertThat(repo().activeForSubjectAndDevice("alice", DEV_X).block()).isNotNull();
        }

        @Test
        void absentGrant_entitlementIsEmpty_defaultNone() {
            // no grant -> entitlement empty (DEFAULT NONE = no sudo).
            StepVerifier.create(repo().activeForSubjectAndDevice("nobody", DEV_X)).verifyComplete();
        }
    }

    // ── MULTIUSER/CROSS-USER: revoke removes the entitlement ─────────────────────

    @Nested
    class RevokeRemovesEntitlement {
        @Test
        void revoke_thenEntitlementIsNone() {
            DesktopSudoGrantRepository r = repo();
            DesktopSudoGrant g = r.insertActive("alice", DEV_X, "brandx", "root", 1L).block();
            assertThat(r.revoke(g.id(), "root", 2L, superadmin()).block()).isEqualTo(1L);
            // revoked grant -> entitlement NONE (the claim source is empty).
            StepVerifier.create(r.activeForSubjectAndDevice("alice", DEV_X)).verifyComplete();
            // the row still exists (audit) but state=revoked.
            assertThat(r.findById(g.id()).block().isActive()).isFalse();
        }

        @Test
        void scopedAdmin_cannotRevokeOtherBrandGrant() {
            DesktopSudoGrantRepository r = repo();
            DesktopSudoGrant gy = r.insertActive("bob", DEV_Y, "brandy", "root", 1L).block();
            // a brand-X scoped admin cannot revoke a brand-Y grant (rows-updated 0).
            assertThat(r.revoke(gy.id(), "x-admin", 2L, admin("https://idp.brandx.example")).block())
                    .isEqualTo(0L);
            assertThat(r.findById(gy.id()).block().isActive()).isTrue();   // untouched
        }
    }

    // ── CONCURRENT / conflicting: CAS revoke single-winner ───────────────────────

    @Nested
    class CasSingleWinner {
        @Test
        void revoke_isSingleWinner() {
            DesktopSudoGrantRepository r = repo();
            DesktopSudoGrant g = r.insertActive("alice", DEV_X, "brandx", "root", 1L).block();
            // first revoke wins; a second (already revoked) is a no-op.
            assertThat(r.revoke(g.id(), "root", 2L, superadmin()).block()).isEqualTo(1L);
            assertThat(r.revoke(g.id(), "root", 3L, superadmin()).block()).isEqualTo(0L);
        }
    }
}
