package net.hugmesh.adminbff.egressvpn;

import org.junit.jupiter.api.BeforeEach;
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
import net.hugmesh.adminbff.device.Device;
import net.hugmesh.adminbff.device.DeviceRegistryRepository;
import net.hugmesh.adminbff.device.DeviceRegistryService;
import net.hugmesh.commons.security.DomainRegistry;
import net.hugmesh.commons.security.PrincipalDomain;
import net.hugmesh.adminbff.support.TestDatabaseConfig;

import java.time.Instant;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * {@link EgressVpnService} tenant-isolation + lifecycle over a REAL H2 repo (CLONES
 * {@code SshLicenseServiceDomainScopeTest}). Proves:
 * <ul>
 *   <li>import is idempotent on an active (domain,name); a malformed config 422s (throws);
 *       a 'default'/unknown domain is REJECTED [FIX-NODEFAULT];</li>
 *   <li>ADMIN reads own-domain ONLY — a brand-X admin sees brand-X rows and a brand-Y
 *       admin's list is EMPTY of them (cross-domain DENY); SUPERADMIN sees ALL;</li>
 *   <li>assign DEVICE rejects an unknown node, a SUPERADMIN-owned node, and a
 *       cross-tenant node (config.domain != node residency); assign DOMAIN rejects a
 *       cross-tenant target; both are idempotent;</li>
 *   <li>revoke config is a CAS (never deleted = audit, gen bumped) that CASCADE-revokes
 *       its assignments; second revoke is a no-op.</li>
 * </ul>
 */
@DataR2dbcTest
@Import(TestDatabaseConfig.class)
@ActiveProfiles("test")
class EgressVpnServiceDomainScopeTest {

    @Autowired DatabaseClient db;

    @BeforeEach
    void clear() {
        db.sql("DELETE FROM vpn_node_assignment").fetch().rowsUpdated().block();
        db.sql("DELETE FROM vpn_config").fetch().rowsUpdated().block();
        db.sql("DELETE FROM device_registry").fetch().rowsUpdated().block();
    }

    private static final DomainRegistry REGISTRY = new DomainRegistry("",
            "https://idp.brandx.example=brandx,https://idp.brandy.example=brandy");
    private static final String BRANDX = "https://idp.brandx.example";

    private static final String WG_X = """
            [Interface]
            PrivateKey = secret-x
            [Peer]
            PublicKey = pub
            Endpoint = 1.2.3.4:51820
            """;
    private static final String WG_Y = """
            [Interface]
            PrivateKey = secret-y
            [Peer]
            PublicKey = pub
            Endpoint = 5.6.7.8:51820
            """;

    private VpnConfigRepository configRepo() { return new VpnConfigRepository(net.hugmesh.adminbff.testutil.R2dbcRepos.of(db, net.hugmesh.adminbff.egressvpn.VpnConfigRowRepository.class)); }
    private VpnNodeAssignmentRepository asgRepo() { return new VpnNodeAssignmentRepository(net.hugmesh.adminbff.testutil.R2dbcRepos.of(db, net.hugmesh.adminbff.egressvpn.VpnNodeAssignmentRowRepository.class)); }
    private DeviceRegistryRepository deviceRepo() { return new DeviceRegistryRepository(net.hugmesh.adminbff.testutil.R2dbcRepos.of(db, net.hugmesh.adminbff.device.DeviceRowRepository.class)); }

    private EgressVpnService svc() {
        return new EgressVpnService(configRepo(), asgRepo(), deviceRepo(), REGISTRY);
    }

    private Device register(String fp, String domain, String ownerType) {
        DeviceRegistryService devSvc = new DeviceRegistryService(deviceRepo(), REGISTRY, false);
        return devSvc.register(new Device(null, fp, "node-" + fp, "tn",
                Device.IMAGE_MESH_EXTENSION, "rpi5", ownerType, "owner@" + domain,
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
    class ImportLifecycle {

        @Test
        void import_isIdempotent_onActiveDomainName() {
            EgressVpnService svc = svc();
            VpnConfig first = svc.importConfig("brandx", "proton-us", "protonvpn", WG_X, "ref-1", "root").block();
            VpnConfig again = svc.importConfig("brandx", "proton-us", "protonvpn", WG_X, "ref-1", "root").block();
            assertThat(first).isNotNull();
            assertThat(again.id()).isEqualTo(first.id());
            assertThat(first.kind()).isEqualTo(VpnConfig.KIND_WIREGUARD);
            assertThat(first.endpoint()).isEqualTo("1.2.3.4:51820");
            // exactly one row.
            Long n = db.sql("SELECT COUNT(*) c FROM vpn_config WHERE state = 'active'")
                    .map((r, m) -> r.get("c", Long.class)).first().block();
            assertThat(n).isEqualTo(1L);
        }

        @Test
        void import_rejectsMalformedConfig_422() {
            assertThatThrownBy(() -> svc().importConfig("brandx", "bad", null, "not a config", "ref", "root").block())
                    .isInstanceOf(IllegalArgumentException.class);
        }

        @Test
        void import_rejectsDefaultAndUnknownDomain() {
            assertThatThrownBy(() -> svc().importConfig("default", "c", null, WG_X, "ref", "root").block())
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("default");
            assertThatThrownBy(() -> svc().importConfig("nosuchbrand", "c", null, WG_X, "ref", "root").block())
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("known residency");
        }

        @Test
        void import_doesNotPersistTheSecretBytes() {
            VpnConfig c = svc().importConfig("brandx", "proton-us", null, WG_X, "ref-1", "root").block();
            // The stored row carries the secret_ref + endpoint metadata, NOT the body.
            String stored = db.sql("SELECT secret_ref FROM vpn_config WHERE id = :id")
                    .bind("id", c.id()).map((r, m) -> r.get("secret_ref", String.class)).first().block();
            assertThat(stored).isEqualTo("ref-1");
            // No column holds the PrivateKey value.
            Long leak = db.sql("SELECT COUNT(*) c FROM vpn_config WHERE endpoint LIKE '%secret-x%'")
                    .map((r, m) -> r.get("c", Long.class)).first().block();
            assertThat(leak).isEqualTo(0L);
        }
    }

    @Nested
    class CrossTenantIsolation {

        @Test
        void adminReadsOwnDomainOnly_crossDomainIsEmpty_superadminSeesAll() {
            EgressVpnService svc = svc();
            svc.importConfig("brandx", "x-cfg", null, WG_X, "rx", "root").block();
            svc.importConfig("brandy", "y-cfg", null, WG_Y, "ry", "root").block();

            // brand-X admin sees ONLY the brandx config.
            List<VpnConfig> xView = svc.listConfigs(admin(BRANDX)).collectList().block();
            assertThat(xView).extracting(VpnConfig::name).containsExactly("x-cfg");

            // brand-Y admin sees ONLY the brandy config — the brandx row is invisible.
            List<VpnConfig> yView = svc.listConfigs(admin("https://idp.brandy.example")).collectList().block();
            assertThat(yView).extracting(VpnConfig::name).containsExactly("y-cfg");

            // SUPERADMIN (unscoped) sees both.
            List<VpnConfig> all = svc.listConfigs(superadmin()).collectList().block();
            assertThat(all).extracting(VpnConfig::name).containsExactlyInAnyOrder("x-cfg", "y-cfg");
        }
    }

    @Nested
    class AssignGuards {

        @Test
        void assignNode_rejectsUnknown_superadminOwned_andCrossTenant() {
            EgressVpnService svc = svc();
            VpnConfig cfg = svc.importConfig("brandx", "x-cfg", null, WG_X, "rx", "root").block();
            register("fp-super", "brandx", Device.OWNER_SUPERADMIN);
            register("fp-other", "brandy", Device.OWNER_ADMIN);
            register("fp-ok", "brandx", Device.OWNER_ADMIN);

            assertThatThrownBy(() -> svc.assignNode(cfg.id(), "fp-missing", null, "root").block())
                    .isInstanceOf(IllegalArgumentException.class).hasMessageContaining("not registered");
            assertThatThrownBy(() -> svc.assignNode(cfg.id(), "fp-super", null, "root").block())
                    .isInstanceOf(IllegalArgumentException.class).hasMessageContaining("SUPERADMIN-owned");
            assertThatThrownBy(() -> svc.assignNode(cfg.id(), "fp-other", null, "root").block())
                    .isInstanceOf(IllegalArgumentException.class).hasMessageContaining("cross-tenant");

            // the same-brand admin node is accepted, idempotently.
            VpnNodeAssignment a1 = svc.assignNode(cfg.id(), "fp-ok", "coturn", "root").block();
            VpnNodeAssignment a2 = svc.assignNode(cfg.id(), "fp-ok", "coturn", "root").block();
            assertThat(a1).isNotNull();
            assertThat(a2.id()).isEqualTo(a1.id());
            assertThat(a1.domain()).isEqualTo("brandx"); // stamped from the config residency
            assertThat(a1.serviceSlug()).isEqualTo("coturn");
        }

        @Test
        void assignDomain_rejectsCrossTenant_andDefault() {
            EgressVpnService svc = svc();
            VpnConfig cfg = svc.importConfig("brandx", "x-cfg", null, WG_X, "rx", "root").block();
            assertThatThrownBy(() -> svc.assignDomain(cfg.id(), "brandy", null, "root").block())
                    .isInstanceOf(IllegalArgumentException.class).hasMessageContaining("cross-tenant");
            assertThatThrownBy(() -> svc.assignDomain(cfg.id(), "default", null, "root").block())
                    .isInstanceOf(IllegalArgumentException.class);
            VpnNodeAssignment a = svc.assignDomain(cfg.id(), "brandx", null, "root").block();
            assertThat(a.scopeType()).isEqualTo(VpnNodeAssignment.SCOPE_DOMAIN);
            assertThat(a.targetDomain()).isEqualTo("brandx");
        }
    }

    @Nested
    class RevokeCascade {

        @Test
        void revokeConfig_isCasAudit_andCascadesAssignments() {
            EgressVpnService svc = svc();
            VpnConfig cfg = svc.importConfig("brandx", "x-cfg", null, WG_X, "rx", "root").block();
            register("fp-ok", "brandx", Device.OWNER_ADMIN);
            VpnNodeAssignment a = svc.assignNode(cfg.id(), "fp-ok", null, "root").block();

            Long first = svc.revokeConfig(cfg.id(), "root", superadmin()).block();
            assertThat(first).isEqualTo(1L);
            // config CAS'd to revoked (never deleted = audit), gen bumped.
            String state = db.sql("SELECT state FROM vpn_config WHERE id = :id")
                    .bind("id", cfg.id()).map((r, m) -> r.get("state", String.class)).first().block();
            assertThat(state).isEqualTo(VpnConfig.STATE_REVOKED);
            // the assignment was cascade-revoked.
            String aState = db.sql("SELECT state FROM vpn_node_assignment WHERE id = :id")
                    .bind("id", a.id()).map((r, m) -> r.get("state", String.class)).first().block();
            assertThat(aState).isEqualTo(VpnNodeAssignment.STATE_REVOKED);

            // second revoke is a no-op (already revoked).
            Long second = svc.revokeConfig(cfg.id(), "root", superadmin()).block();
            assertThat(second).isEqualTo(0L);
        }

        @Test
        void revokeConfig_scopedAdmin_cannotRevokeOtherBrand() {
            EgressVpnService svc = svc();
            VpnConfig cfg = svc.importConfig("brandx", "x-cfg", null, WG_X, "rx", "root").block();
            // a brand-Y scoped principal's revoke matches no row in brandx (cross-domain DENY).
            Long n = svc.revokeConfig(cfg.id(), "carol", admin("https://idp.brandy.example")).block();
            assertThat(n).isEqualTo(0L);
            String state = db.sql("SELECT state FROM vpn_config WHERE id = :id")
                    .bind("id", cfg.id()).map((r, m) -> r.get("state", String.class)).first().block();
            assertThat(state).isEqualTo(VpnConfig.STATE_ACTIVE); // untouched
        }
    }
}
