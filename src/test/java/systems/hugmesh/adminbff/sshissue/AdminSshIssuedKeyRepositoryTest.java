package systems.hugmesh.adminbff.sshissue;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
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
 * The admin_ssh_issued_key R2DBC repository over a Liquibase-applied H2 (PG-compat) — proves
 * the 172 changelog applies (table + state CHECK + device/license FKs) and the
 * device_ssh_license-cloned idiom round-trips. A device_registry + device_ssh_license parent
 * row is seeded for the FKs.
 *
 * <p>Per the test-standard: USER-SITUATIONAL (insert/list), MULTIUSER (markDownloaded
 * single-winner = single-use audit), CROSS-USER (scoped revoke can't touch another brand),
 * CONCURRENT (CAS revoke single-winner). The NO-PRIVATE-KEY-PERSISTENCE invariant is asserted
 * structurally (no such column).
 */
@DataR2dbcTest
@Import(TestDatabaseConfig.class)
@ActiveProfiles("test")
class AdminSshIssuedKeyRepositoryTest {

    @Autowired DatabaseClient db;

    private static final String DEV_X = "dev-x-1";
    private static final String DEV_Y = "dev-y-1";
    private String licX;
    private String licY;

    @BeforeEach
    void seed() {
        db.sql("DELETE FROM admin_ssh_issued_key").fetch().rowsUpdated().block();
        db.sql("DELETE FROM device_ssh_license").fetch().rowsUpdated().block();
        db.sql("DELETE FROM device_registry").fetch().rowsUpdated().block();
        insertDevice(DEV_X, "fp-x", "brandx");
        insertDevice(DEV_Y, "fp-y", "brandy");
        licX = insertLicense(DEV_X, "brandx", "SHA256:aaa");
        licY = insertLicense(DEV_Y, "brandy", "SHA256:bbb");
    }

    @AfterEach
    void cleanup() {
        // FK-safe teardown so the SHARED H2 context does not leak device_ssh_license /
        // admin_ssh_issued_key rows referencing dev-x-1/dev-y-1 into the next @DataR2dbcTest
        // class (whose device_registry cleanup does not clear these child tables).
        db.sql("DELETE FROM admin_ssh_issued_key").fetch().rowsUpdated().block();
        db.sql("DELETE FROM device_ssh_license").fetch().rowsUpdated().block();
        db.sql("DELETE FROM device_registry").fetch().rowsUpdated().block();
    }

    private void insertDevice(String id, String fp, String domain) {
        db.sql("INSERT INTO device_registry "
                        + "(id, machine_key_fp, hostname, image_type, owner_type, physical_owner, domain, mesh_id) "
                        + "VALUES (:id, :fp, :h, 'client', 'ADMIN', 'o', :domain, 'mesh-1')")
                .bind("id", id).bind("fp", fp).bind("h", id).bind("domain", domain)
                .fetch().rowsUpdated().block();
    }

    private String insertLicense(String deviceId, String domain, String fps) {
        String id = "lic-" + deviceId;
        db.sql("INSERT INTO device_ssh_license "
                        + "(id, operator, scope_type, device_id, key_fingerprints, state, granted_by, "
                        + " granted_at, domain, propagation_state, generation) "
                        + "VALUES (:id, 'op', 'DEVICE', :dev, :fps, 'active', 'sa', now(), :domain, 'pending', 1)")
                .bind("id", id).bind("dev", deviceId).bind("fps", fps).bind("domain", domain)
                .fetch().rowsUpdated().block();
        return id;
    }

    private AdminSshIssuedKeyRepository repo() {
        return new AdminSshIssuedKeyRepository(systems.hugmesh.adminbff.testutil.R2dbcRepos.of(db, systems.hugmesh.adminbff.sshissue.AdminSshIssuedKeyRowRepository.class));
    }

    private AdminSshIssuedKey draft(String deviceId, String licenseId, String operator,
                                    String domain, String fp) {
        return new AdminSshIssuedKey(null, deviceId, licenseId, operator,
                AdminSshIssuedKey.KEY_TYPE_ED25519, "ssh-ed25519 AAAA" + fp, fp,
                operator, null, null, AdminSshIssuedKey.STATE_ISSUED, domain, null, null);
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

    // ── USER-SITUATIONAL ─────────────────────────────────────────────────────────
    @Nested
    class InsertAndRead {
        @Test
        void insert_roundTrips_andActiveForDeviceResolves() {
            AdminSshIssuedKey k = repo().insert(draft(DEV_X, licX, "alice", "brandx", "SHA256:ccc")).block();
            assertThat(k.id()).isNotBlank();
            assertThat(k.isIssued()).isTrue();
            assertThat(k.isDownloaded()).isFalse();
            assertThat(k.domain()).isEqualTo("brandx");
            assertThat(repo().findActiveForDevice(DEV_X, superadmin()).collectList().block()).hasSize(1);
        }

        @Test
        void noPrivateKeyColumn_existsOnTheTable() {
            // NO-PRIVATE-KEY-PERSISTENCE: the audit table has no private-key column (structural).
            Long cnt = db.sql("SELECT COUNT(*) AS c FROM information_schema.columns "
                            + "WHERE upper(table_name) = 'ADMIN_SSH_ISSUED_KEY' "
                            + "AND (upper(column_name) LIKE '%PRIVATE%' OR upper(column_name) LIKE '%SECRET%')")
                    .map((row, meta) -> row.get("c", Long.class)).first().block();
            assertThat(cnt).isZero();
        }
    }

    // ── MULTIUSER: single-use download stamp ───────────────────────────────────────
    @Nested
    class SingleUseDownload {
        @Test
        void markDownloaded_isSingleWinner() {
            AdminSshIssuedKey k = repo().insert(draft(DEV_X, licX, "alice", "brandx", "SHA256:ddd")).block();
            assertThat(repo().markDownloaded(k.id()).block()).isEqualTo(1L);   // first wins
            assertThat(repo().markDownloaded(k.id()).block()).isEqualTo(0L);   // second is a no-op
            assertThat(repo().findById(k.id()).block().isDownloaded()).isTrue();
        }
    }

    // ── MULTIUSER/CROSS-USER: revoke ────────────────────────────────────────────────
    @Nested
    class Revoke {
        @Test
        void revoke_flipsState_neverDeletes() {
            AdminSshIssuedKeyRepository r = repo();
            AdminSshIssuedKey k = r.insert(draft(DEV_X, licX, "alice", "brandx", "SHA256:eee")).block();
            assertThat(r.revoke(k.id(), "sa", superadmin()).block()).isEqualTo(1L);
            // row still exists (audit) but state=revoked + no longer in the active view.
            assertThat(r.findById(k.id()).block().isIssued()).isFalse();
            assertThat(r.findActiveForDevice(DEV_X, superadmin()).collectList().block()).isEmpty();
        }

        @Test
        void scopedAdmin_cannotRevokeOtherBrandRow() {
            AdminSshIssuedKeyRepository r = repo();
            AdminSshIssuedKey ky = r.insert(draft(DEV_Y, licY, "bob", "brandy", "SHA256:fff")).block();
            // a brand-X scoped admin cannot revoke a brand-Y row (rows-updated 0).
            assertThat(r.revoke(ky.id(), "x-admin", admin("https://idp.brandx.example")).block()).isEqualTo(0L);
            assertThat(r.findById(ky.id()).block().isIssued()).isTrue();   // untouched
        }

        @Test
        void revoke_isSingleWinner() {
            AdminSshIssuedKeyRepository r = repo();
            AdminSshIssuedKey k = r.insert(draft(DEV_X, licX, "alice", "brandx", "SHA256:ggg")).block();
            assertThat(r.revoke(k.id(), "sa", superadmin()).block()).isEqualTo(1L);
            assertThat(r.revoke(k.id(), "sa", superadmin()).block()).isEqualTo(0L);
        }
    }

    // ── CROSS-USER: scoped list isolation ──────────────────────────────────────────
    @Nested
    class ScopedList {
        @Test
        void scopedAdmin_seesOnlyOwnBrand() {
            AdminSshIssuedKeyRepository r = repo();
            r.insert(draft(DEV_X, licX, "alice", "brandx", "SHA256:h1")).block();
            // brand-Y admin sees nothing on DEV_X (cross-brand); brand-X admin sees the row.
            StepVerifier.create(r.findActiveForDevice(DEV_X, admin("https://idp.brandy.example")))
                    .verifyComplete();
            assertThat(r.findActiveForDevice(DEV_X, admin("https://idp.brandx.example")).collectList().block())
                    .hasSize(1);
        }
    }
}
