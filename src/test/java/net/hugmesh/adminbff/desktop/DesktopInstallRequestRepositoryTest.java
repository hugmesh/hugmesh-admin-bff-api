package net.hugmesh.adminbff.desktop;

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
import net.hugmesh.commons.security.DomainRegistry;
import net.hugmesh.commons.security.PrincipalDomain;
import net.hugmesh.adminbff.support.DeviceRegistryCleanup;
import net.hugmesh.adminbff.support.DeviceRegistryCleanupConfig;
import net.hugmesh.adminbff.support.TestDatabaseConfig;

import java.time.Instant;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The desktop_install_request R2DBC repository over a Liquibase-applied H2 (PG-compat) —
 * proves the 142 changelog applies (table + status CHECK + FK) and the owner==subject +
 * brand-scope + decide-CAS idioms round-trip.
 *
 * <p>Per the test-standard, the CROSS-USER isolation keystone: a user sees ONLY their OWN
 * requests (negative isolation); the admin decide is brand-scoped + single-winner.
 */
@DataR2dbcTest
@Import({TestDatabaseConfig.class, DeviceRegistryCleanupConfig.class})
@ActiveProfiles("test")
class DesktopInstallRequestRepositoryTest {

    @Autowired DatabaseClient db;

    @Autowired DeviceRegistryCleanup deviceRegistryCleanup;

    private static final String DEV_X = "dev-x-1";
    private static final String DEV_Y = "dev-y-1";

    @BeforeEach
    void seed() {
        db.sql("DELETE FROM desktop_install_request").fetch().rowsUpdated().block();
        db.sql("DELETE FROM desktop_sudo_grant").fetch().rowsUpdated().block();
        db.sql("DELETE FROM device_ssh_license").fetch().rowsUpdated().block();
        deviceRegistryCleanup.clearDeviceRegistry().block();
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

    private DesktopInstallRequestRepository repo() {
        return new DesktopInstallRequestRepository(net.hugmesh.adminbff.testutil.R2dbcRepos.of(db, net.hugmesh.adminbff.desktop.DesktopInstallRequestR2dbcRepository.class));
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

    // ── owner == subject (negative cross-user isolation) ─────────────────────────

    @Nested
    class OwnerIsSubject {
        @Test
        void user_seesOnlyOwnRequests() {
            DesktopInstallRequestRepository r = repo();
            r.insertPending("alice", "a.ref", DEV_X, "brandx").block();
            r.insertPending("bob", "b.ref", DEV_X, "brandx").block();
            // alice sees ONLY hers — bob's request is invisible (cross-user DENY).
            assertThat(r.listForRequester("alice", "brandx").collectList().block())
                    .extracting(DesktopInstallRequest::requester).containsExactly("alice");
        }

        @Test
        void user_cannotResolveAnotherUsersRequestById() {
            DesktopInstallRequestRepository r = repo();
            DesktopInstallRequest bobs = r.insertPending("bob", "b.ref", DEV_X, "brandx").block();
            // alice cannot fetch bob's request even by its id (double-scoped requester+domain).
            StepVerifier.create(r.findByIdForRequester(bobs.id(), "alice", "brandx")).verifyComplete();
            // bob can.
            assertThat(r.findByIdForRequester(bobs.id(), "bob", "brandx").block()).isNotNull();
        }
    }

    // ── admin brand-scope + decide CAS ───────────────────────────────────────────

    @Nested
    class AdminScopeAndDecide {
        @Test
        void adminInbox_isBrandScoped() {
            DesktopInstallRequestRepository r = repo();
            r.insertPending("alice", "a.ref", DEV_X, "brandx").block();
            r.insertPending("carol", "c.ref", DEV_Y, "brandy").block();
            assertThat(r.list(admin("https://idp.brandx.example")).collectList().block())
                    .extracting(DesktopInstallRequest::domain).containsOnly("brandx");
            assertThat(r.list(superadmin()).collectList().block())
                    .extracting(DesktopInstallRequest::domain).contains("brandx", "brandy");
        }

        @Test
        void decide_isSingleWinner_andBrandScoped() {
            DesktopInstallRequestRepository r = repo();
            DesktopInstallRequest req = r.insertPending("alice", "a.ref", DEV_X, "brandx").block();
            // first approve wins; a second decide is a no-op (no longer pending).
            assertThat(r.decide(req.id(), "approved", "admin-x", superadmin()).block()).isEqualTo(1L);
            assertThat(r.decide(req.id(), "denied", "admin-x", superadmin()).block()).isEqualTo(0L);
        }

        @Test
        void scopedAdmin_cannotDecideOtherBrandRequest() {
            DesktopInstallRequestRepository r = repo();
            DesktopInstallRequest reqY = r.insertPending("carol", "c.ref", DEV_Y, "brandy").block();
            // a brand-X admin cannot decide a brand-Y request (rows-updated 0).
            assertThat(r.decide(reqY.id(), "approved", "x-admin", admin("https://idp.brandx.example")).block())
                    .isEqualTo(0L);
        }
    }
}
