package net.hugmesh.adminbff.device;

import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.data.r2dbc.test.autoconfigure.DataR2dbcTest;
import org.springframework.context.annotation.Import;
import org.springframework.r2dbc.core.DatabaseClient;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.test.context.ActiveProfiles;
import net.hugmesh.commons.security.DomainRegistry;
import net.hugmesh.commons.security.PrincipalDomain;
import net.hugmesh.adminbff.support.TestDatabaseConfig;

import java.time.Instant;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * {@link SshLicenseService} tenant-isolation + lifecycle over a REAL H2 repo. Proves:
 * <ul>
 *   <li>idempotent grant (findActive-then-insert) — a re-grant of the same
 *       (operator,device) returns the existing active row (no duplicate);</li>
 *   <li>CAS revoke — first revoke wins (1 row, state→revoked, gen bumped, audited),
 *       second is a no-op (0 rows); the row is NEVER deleted (audit trail);</li>
 *   <li>ADMIN reads own-domain ONLY — a brand-X admin sees brand-X license rows and a
 *       brand-Y admin's list is EMPTY of them (cross-domain DENY); SUPERADMIN sees all;</li>
 *   <li>POST-VERIFY CORRECTION (2026-06-12): a DEVICE grant on a SUPERADMIN-owned device is
 *       REJECTED (and writes NO row) — superadmin reach is mesh-membership, not a license;
 *       a DOMAIN grant on {@code 'default'}/blank/unknown is REJECTED [FIX-NODEFAULT];
 *       {@code license.domain} is stamped from the device's residency, never the caller.</li>
 * </ul>
 */
@DataR2dbcTest
@Import(TestDatabaseConfig.class)
@ActiveProfiles("test")
class SshLicenseServiceDomainScopeTest {

    @Autowired DatabaseClient db;

    @org.junit.jupiter.api.BeforeEach
    void clear() {
        db.sql("DELETE FROM device_ssh_license").fetch().rowsUpdated().block();
        db.sql("DELETE FROM device_registry").fetch().rowsUpdated().block();
    }

    private static final DomainRegistry REGISTRY = new DomainRegistry("",
            "https://idp.brandx.example=brandx,https://idp.brandy.example=brandy");
    private static final String BRANDX = "https://idp.brandx.example";
    private static final String BRANDY = "https://idp.brandy.example";

    private DeviceRegistryRepository deviceRepo() { return new DeviceRegistryRepository(net.hugmesh.adminbff.testutil.R2dbcRepos.of(db, net.hugmesh.adminbff.device.DeviceRowRepository.class)); }
    private SshLicenseRepository licenseRepo() { return new SshLicenseRepository(net.hugmesh.adminbff.testutil.R2dbcRepos.of(db, net.hugmesh.adminbff.device.SshLicenseRowRepository.class)); }
    private SshLicenseService svc() {
        return new SshLicenseService(licenseRepo(), deviceRepo(), REGISTRY);
    }

    private Device register(String fp, String domain) {
        return register(fp, domain, Device.OWNER_ADMIN, Device.IMAGE_MESH_EXTENSION);
    }

    private Device register(String fp, String domain, String ownerType, String imageType) {
        DeviceRegistryService devSvc = new DeviceRegistryService(deviceRepo(), REGISTRY, false);
        return devSvc.register(new Device(null, fp, "node-" + fp, "tn",
                imageType, "rpi5", ownerType, "owner@" + domain,
                domain, "mesh-1", null, null)).block();
    }

    private static PrincipalDomain admin(String issuer) {
        Jwt jwt = Jwt.withTokenValue("t").header("alg", "none")
                .issuedAt(Instant.now()).expiresAt(Instant.now().plusSeconds(3600))
                .subject("u").issuer(issuer).claim("roles", List.of("admin")).build();
        var auth = new JwtAuthenticationToken(jwt,
                List.of(new SimpleGrantedAuthority("ROLE_USER"), new SimpleGrantedAuthority("ROLE_ADMIN")));
        return PrincipalDomain.of(auth, REGISTRY);
    }

    private static PrincipalDomain superadmin() {
        Jwt jwt = Jwt.withTokenValue("t").header("alg", "none")
                .issuedAt(Instant.now()).expiresAt(Instant.now().plusSeconds(3600))
                .subject("u").issuer(BRANDX).claim("roles", List.of("superadmin")).build();
        var auth = new JwtAuthenticationToken(jwt,
                List.of(new SimpleGrantedAuthority("ROLE_USER"), new SimpleGrantedAuthority("ROLE_SUPERADMIN")));
        return PrincipalDomain.of(auth, REGISTRY);
    }

    @Nested
    class GrantIdempotency {

        @Test
        void grantDevice_isIdempotent_onActiveOperatorDevice() {
            SshLicenseService svc = svc();
            Device d = register("fp-x", "brandx");

            SshLicense first = svc.grantDevice("bob@brandx", d.id(), List.of("SHA256:k1"), "root").block();
            SshLicense again = svc.grantDevice("bob@brandx", d.id(), List.of("SHA256:k1"), "root").block();

            // Same active row returned — no duplicate active license.
            assertThat(again.id()).isEqualTo(first.id());
            Long active = db.sql("SELECT COUNT(*) AS c FROM device_ssh_license "
                            + "WHERE operator = 'bob@brandx' AND device_id = :dev AND state = 'active'")
                    .bind("dev", d.id())
                    .map((r, m) -> r.get("c", Long.class)).first().block();
            assertThat(active).isEqualTo(1L);
        }

        @Test
        void grantDevice_stampsTheDeviceResidencyDomain_notTheGranter() {
            SshLicenseService svc = svc();
            Device d = register("fp-y", "brandy");
            // A superadmin grants on a brandy device — the license lands in brandy.
            SshLicense lic = svc.grantDevice("carol@brandy", d.id(), List.of("SHA256:k2"), "root").block();
            assertThat(lic.domain()).isEqualTo("brandy");
        }

        @Test
        void grantDomain_isIdempotent_andPinsKey() {
            SshLicenseService svc = svc();
            SshLicense first = svc.grantDomain("dave@brandx", "brandx", List.of("SHA256:dk"), "root").block();
            SshLicense again = svc.grantDomain("dave@brandx", "brandx", List.of("SHA256:dk"), "root").block();
            assertThat(again.id()).isEqualTo(first.id());
            assertThat(first.keyFingerprints()).isEqualTo("SHA256:dk");   // FIX-PINKEY pinned
            assertThat(first.domain()).isEqualTo("brandx");
        }
    }

    // ════════════════ POST-VERIFY CORRECTION (2026-06-12) ══════════════════════════
    @Nested
    class SuperadminOwnedDeviceAndDomainValidation {

        @Test
        void grantDevice_onSuperadminOwnedDevice_isRejected_andWritesNoLicenseRow() {
            // (a) A device-license on a SUPERADMIN-owned (core) node is NEVER valid:
            // superadmin reach is mesh-membership, not a license. The grant is rejected and
            // emits NO row — so the node never appears in the signed export (the export
            // cannot see operator roles, so it must carry no SUPERADMIN access).
            SshLicenseService svc = svc();
            Device core = register("fp-core", "brandx", Device.OWNER_SUPERADMIN, Device.IMAGE_PRIMARY);

            assertThatThrownBy(() ->
                    svc.grantDevice("ops@brandx", core.id(), List.of("SHA256:sk"), "root").block())
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("SUPERADMIN-owned");

            // No license row was written for the rejected grant.
            Long rows = db.sql("SELECT COUNT(*) AS c FROM device_ssh_license WHERE device_id = :dev")
                    .bind("dev", core.id())
                    .map((r, m) -> r.get("c", Long.class)).first().block();
            assertThat(rows).isEqualTo(0L);
        }

        @Test
        void grantDevice_onAdminOwnedDevice_stampsLicenseDomainFromDeviceResidency_notCaller() {
            // (d) license.domain is stamped from the RESOLVED device residency, so a DEVICE
            // license can never claim a different domain than its device.
            SshLicenseService svc = svc();
            Device d = register("fp-res", "brandy");   // ADMIN-owned brandy device
            SshLicense lic = svc.grantDevice("carol@brandy", d.id(), List.of("SHA256:k"), "root").block();
            assertThat(lic.domain()).isEqualTo("brandy");
            assertThat(lic.isDeviceScoped()).isTrue();
        }

        @Test
        void grantDevice_onUnregisteredDevice_isRejected() {
            SshLicenseService svc = svc();
            assertThatThrownBy(() ->
                    svc.grantDevice("ops@brandx", "no-such-device", List.of("SHA256:k"), "root").block())
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("not registered");
        }

        @Test
        void grantDomain_rejectsDefault_andBlank_andUnknownDomain() {
            // (d) [FIX-NODEFAULT]: a DOMAIN-license target must be a real, known residency
            // brand — never 'default'/blank/unknown. REGISTRY knows {brandx, brandy} only.
            SshLicenseService svc = svc();

            assertThatThrownBy(() ->
                    svc.grantDomain("dave@x", "default", List.of("SHA256:k"), "root").block())
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("default");

            assertThatThrownBy(() ->
                    svc.grantDomain("dave@x", "  ", List.of("SHA256:k"), "root").block())
                    .isInstanceOf(IllegalArgumentException.class);

            assertThatThrownBy(() ->
                    svc.grantDomain("dave@x", "brandz", List.of("SHA256:k"), "root").block())
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("not a known residency domain");

            // No row was written for any rejected DOMAIN grant.
            Long rows = db.sql("SELECT COUNT(*) AS c FROM device_ssh_license WHERE scope_type = 'DOMAIN'")
                    .map((r, m) -> r.get("c", Long.class)).first().block();
            assertThat(rows).isEqualTo(0L);
        }

        @Test
        void grantDomain_onKnownBrand_succeeds() {
            // The happy path still works for a real, known brand.
            SshLicenseService svc = svc();
            SshLicense lic = svc.grantDomain("dave@brandx", "brandx", List.of("SHA256:k"), "root").block();
            assertThat(lic).isNotNull();
            assertThat(lic.domain()).isEqualTo("brandx");
            assertThat(lic.isDomainScoped()).isTrue();
        }
    }

    @Nested
    class CasRevoke {

        @Test
        void revoke_isCompareAndSwap_winnerThenNoop_neverDeletes_bumpsGeneration() {
            SshLicenseService svc = svc();
            Device d = register("fp-r", "brandx");
            SshLicense lic = svc.grantDevice("bob@brandx", d.id(), List.of("SHA256:k"), "root").block();
            long genBefore = lic.generation();

            // First revoke wins, second is a no-op (the single-revoke guard).
            assertThat(svc.revoke(lic.id(), "root", superadmin()).block()).isEqualTo(1L);
            assertThat(svc.revoke(lic.id(), "root", superadmin()).block()).isEqualTo(0L);

            // Row is NOT deleted — it is the audit trail (state revoked, revoked_by + gen
            // bumped, propagation back to pending for the push-with-ack).
            SshLicense after = licenseRepo().findById(lic.id()).block();
            assertThat(after).isNotNull();
            assertThat(after.state()).isEqualTo(SshLicense.STATE_REVOKED);
            assertThat(after.revokedBy()).isEqualTo("root");
            assertThat(after.generation()).isGreaterThan(genBefore);
            assertThat(after.propagationState()).isEqualTo(SshLicense.PROP_PENDING);
        }
    }

    @Nested
    class TenantIsolation {

        @Test
        void adminReadsOwnDomainOnly_crossDomainIsEmpty_superadminSeesAll() {
            SshLicenseService svc = svc();
            Device dx = register("fp-bx", "brandx");
            Device dy = register("fp-by", "brandy");
            svc.grantDevice("bob@brandx", dx.id(), List.of("SHA256:x"), "root").block();
            svc.grantDevice("carol@brandy", dy.id(), List.of("SHA256:y"), "root").block();

            // brand-X admin sees ONLY the brandx license.
            List<SshLicense> xView = svc.list(admin(BRANDX)).collectList().block();
            assertThat(xView).extracting(SshLicense::operator).containsExactly("bob@brandx");

            // brand-Y admin sees ONLY the brandy license — the brandx row is invisible
            // (cross-domain DENY).
            List<SshLicense> yView = svc.list(admin(BRANDY)).collectList().block();
            assertThat(yView).extracting(SshLicense::operator).containsExactly("carol@brandy");

            // SUPERADMIN (unscoped) sees both.
            List<SshLicense> all = svc.list(superadmin()).collectList().block();
            assertThat(all).extracting(SshLicense::operator)
                    .containsExactlyInAnyOrder("bob@brandx", "carol@brandy");
        }

        @Test
        void activeForDevice_isScoped_crossDomainEmpty() {
            SshLicenseService svc = svc();
            Device dx = register("fp-afd", "brandx");
            svc.grantDevice("bob@brandx", dx.id(), List.of("SHA256:x"), "root").block();

            assertThat(svc.activeForDevice(dx.id(), admin(BRANDX)).collectList().block()).hasSize(1);
            // A brand-Y admin cannot see the brandx device's grants.
            assertThat(svc.activeForDevice(dx.id(), admin(BRANDY)).collectList().block()).isEmpty();
        }
    }
}
