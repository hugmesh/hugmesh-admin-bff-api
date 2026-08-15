package net.hugmesh.adminbff.egressvpn;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.data.r2dbc.test.autoconfigure.DataR2dbcTest;
import org.springframework.context.annotation.Import;
import org.springframework.r2dbc.core.DatabaseClient;
import org.springframework.test.context.ActiveProfiles;
import reactor.core.publisher.Mono;
import net.hugmesh.adminbff.device.Device;
import net.hugmesh.adminbff.device.DeviceRegistryRepository;
import net.hugmesh.adminbff.device.DeviceRegistryService;
import net.hugmesh.adminbff.support.DeviceRegistryCleanup;
import net.hugmesh.adminbff.support.DeviceRegistryCleanupConfig;
import net.hugmesh.adminbff.support.TestDatabaseConfig;
import net.hugmesh.commons.security.DomainRegistry;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicLong;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * The THREE control-plane seams {@link EgressVpnService} drives, over a REAL H2 repo (the
 * {@code EgressVpnServiceDomainScopeTest} harness):
 * <ul>
 *   <li><b>Secret delivery</b> — a FRESH import hands the validated bytes to the
 *       {@link VpnConfigSecretWriter} exactly once (secretRef + raw body); the idempotent
 *       re-import does NOT re-deliver; a failed delivery NEVER fails the import (the row
 *       stays the committed control record, propagation visibly {@code pending});</li>
 *   <li><b>Labeler fast path</b> — a fresh assign, an un-assign, and the revoke-config
 *       cascade each trigger exactly ONE {@link VpnEgressLabeler#reconcile()}; the
 *       idempotent/lost-CAS no-ops trigger NONE (nothing changed to converge);</li>
 *   <li><b>Node report-back</b> — {@code reportNodeState} flips {@code propagation_state}
 *       on exactly the rows that fed that node's export (DEVICE assignments on the fp +
 *       DOMAIN assignments on the residency + their still-active configs); an unknown fp /
 *       a SUPERADMIN-owned node flips NOTHING (fail-closed 0); an out-of-vocabulary state
 *       throws (-&gt; 422).</li>
 * </ul>
 */
@DataR2dbcTest
@Import({TestDatabaseConfig.class, DeviceRegistryCleanupConfig.class})
@ActiveProfiles("test")
class EgressVpnEffectorSeamsTest {

    @Autowired DatabaseClient db;
    @Autowired DeviceRegistryCleanup deviceRegistryCleanup;

    @BeforeEach
    void clear() {
        db.sql("DELETE FROM vpn_node_assignment").fetch().rowsUpdated().block();
        db.sql("DELETE FROM vpn_config").fetch().rowsUpdated().block();
        deviceRegistryCleanup.clearDeviceRegistry().block();
    }

    private static final DomainRegistry REGISTRY = new DomainRegistry("",
            "https://idp.brandx.example=brandx,https://idp.brandy.example=brandy");

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

    /** Records every delivery (secretRef + body) and answers a configurable applied flag. */
    static class RecordingSecretWriter implements VpnConfigSecretWriter {
        record Delivery(String secretRef, String body) { }
        final List<Delivery> deliveries = new ArrayList<>();
        boolean applied = true;
        @Override
        public Mono<Boolean> write(String secretRef, String domain, String name, String kind,
                                   String configBody) {
            deliveries.add(new Delivery(secretRef, configBody));
            return Mono.just(applied);
        }
        @Override
        public boolean isReal() { return true; }
    }

    /** Counts reconcile() calls (the fast-path trigger probe). */
    static class CountingLabeler implements VpnEgressLabeler {
        final AtomicLong reconciles = new AtomicLong();
        @Override
        public Mono<Long> reconcile() {
            reconciles.incrementAndGet();
            return Mono.just(0L);
        }
        @Override
        public boolean isReal() { return true; }
    }

    private VpnConfigRepository configRepo() { return new VpnConfigRepository(net.hugmesh.adminbff.testutil.R2dbcRepos.of(db, net.hugmesh.adminbff.egressvpn.VpnConfigRowRepository.class)); }
    private VpnNodeAssignmentRepository asgRepo() { return new VpnNodeAssignmentRepository(net.hugmesh.adminbff.testutil.R2dbcRepos.of(db, net.hugmesh.adminbff.egressvpn.VpnNodeAssignmentRowRepository.class)); }
    private DeviceRegistryRepository deviceRepo() { return new DeviceRegistryRepository(net.hugmesh.adminbff.testutil.R2dbcRepos.of(db, net.hugmesh.adminbff.device.DeviceRowRepository.class)); }

    private EgressVpnService svc(VpnConfigSecretWriter writer, VpnEgressLabeler labeler) {
        return new EgressVpnService(configRepo(), asgRepo(), deviceRepo(), REGISTRY, writer, labeler);
    }

    private Device register(String fp, String domain, String ownerType) {
        DeviceRegistryService devSvc = new DeviceRegistryService(deviceRepo(), REGISTRY, false);
        return devSvc.register(new Device(null, fp, "node-" + fp, "tn",
                Device.IMAGE_MESH_EXTENSION, "rpi5", ownerType, "owner@" + domain,
                domain, "mesh-1", null, null)).block();
    }

    private static net.hugmesh.commons.security.PrincipalDomain superadmin() {
        org.springframework.security.oauth2.jwt.Jwt jwt = org.springframework.security.oauth2.jwt.Jwt
                .withTokenValue("t").header("alg", "none")
                .issuedAt(java.time.Instant.now()).expiresAt(java.time.Instant.now().plusSeconds(3600))
                .subject("u").issuer("https://idp.brandx.example")
                .claim("roles", List.of("superadmin")).build();
        var auth = new org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken(
                jwt, List.of(new org.springframework.security.core.authority.SimpleGrantedAuthority("ROLE_USER"),
                        new org.springframework.security.core.authority.SimpleGrantedAuthority("ROLE_SUPERADMIN")));
        return net.hugmesh.commons.security.PrincipalDomain.of(auth, REGISTRY);
    }

    private String propOfConfig(String id) {
        return db.sql("SELECT propagation_state FROM vpn_config WHERE id = :id")
                .bind("id", id).map((r, m) -> r.get("propagation_state", String.class)).first().block();
    }

    private String propOfAssignment(String id) {
        return db.sql("SELECT propagation_state FROM vpn_node_assignment WHERE id = :id")
                .bind("id", id).map((r, m) -> r.get("propagation_state", String.class)).first().block();
    }

    @Nested
    class SecretDelivery {

        @Test
        void freshImport_deliversTheValidatedBytes_exactlyOnce() {
            RecordingSecretWriter writer = new RecordingSecretWriter();
            EgressVpnService svc = svc(writer, new CountingLabeler());

            VpnConfig c = svc.importConfig("brandx", "proton-us", "protonvpn", WG_X, "ref-1", "root").block();

            assertThat(c).isNotNull();
            assertThat(writer.deliveries).hasSize(1);
            assertThat(writer.deliveries.get(0).secretRef()).isEqualTo("ref-1");
            assertThat(writer.deliveries.get(0).body()).isEqualTo(WG_X);
        }

        @Test
        void idempotentReImport_doesNotRedeliver() {
            RecordingSecretWriter writer = new RecordingSecretWriter();
            EgressVpnService svc = svc(writer, new CountingLabeler());

            svc.importConfig("brandx", "proton-us", "protonvpn", WG_X, "ref-1", "root").block();
            // The re-import no-op must NOT overwrite the Secret (a DIFFERENT body under the
            // same (domain,name) would silently diverge row metadata from Secret content).
            svc.importConfig("brandx", "proton-us", "protonvpn", WG_Y, "ref-1", "root").block();

            assertThat(writer.deliveries).hasSize(1);
            assertThat(writer.deliveries.get(0).body()).isEqualTo(WG_X);
        }

        @Test
        void failedDelivery_neverFailsTheImport_rowStaysPending() {
            RecordingSecretWriter writer = new RecordingSecretWriter();
            writer.applied = false;
            EgressVpnService svc = svc(writer, new CountingLabeler());

            VpnConfig c = svc.importConfig("brandx", "proton-us", "protonvpn", WG_X, "ref-1", "root").block();

            assertThat(c).isNotNull();
            assertThat(c.id()).isNotBlank();
            assertThat(propOfConfig(c.id())).isEqualTo(VpnConfig.PROP_PENDING);
        }
    }

    @Nested
    class LabelerFastPath {

        @Test
        void freshAssign_triggersOneReconcile_idempotentReassignTriggersNone() {
            CountingLabeler labeler = new CountingLabeler();
            EgressVpnService svc = svc(new RecordingSecretWriter(), labeler);
            VpnConfig cfg = svc.importConfig("brandx", "x-cfg", null, WG_X, "rx", "root").block();
            register("fp-ok", "brandx", Device.OWNER_ADMIN);

            svc.assignNode(cfg.id(), "fp-ok", "coturn", "root").block();
            assertThat(labeler.reconciles.get()).isEqualTo(1L);

            // idempotent no-op — nothing changed, nothing to converge.
            svc.assignNode(cfg.id(), "fp-ok", "coturn", "root").block();
            assertThat(labeler.reconciles.get()).isEqualTo(1L);

            svc.assignDomain(cfg.id(), "brandx", null, "root").block();
            assertThat(labeler.reconciles.get()).isEqualTo(2L);
        }

        @Test
        void unassign_triggersOneReconcile_lostCasTriggersNone() {
            CountingLabeler labeler = new CountingLabeler();
            EgressVpnService svc = svc(new RecordingSecretWriter(), labeler);
            VpnConfig cfg = svc.importConfig("brandx", "x-cfg", null, WG_X, "rx", "root").block();
            register("fp-ok", "brandx", Device.OWNER_ADMIN);
            VpnNodeAssignment a = svc.assignNode(cfg.id(), "fp-ok", null, "root").block();
            long before = labeler.reconciles.get();

            svc.revokeAssignment(a.id(), "root", superadmin()).block();
            assertThat(labeler.reconciles.get()).isEqualTo(before + 1);

            // second revoke loses the CAS (already revoked) — no trigger.
            svc.revokeAssignment(a.id(), "root", superadmin()).block();
            assertThat(labeler.reconciles.get()).isEqualTo(before + 1);
        }

        @Test
        void revokeConfigCascade_triggersOneReconcile() {
            CountingLabeler labeler = new CountingLabeler();
            EgressVpnService svc = svc(new RecordingSecretWriter(), labeler);
            VpnConfig cfg = svc.importConfig("brandx", "x-cfg", null, WG_X, "rx", "root").block();
            register("fp-ok", "brandx", Device.OWNER_ADMIN);
            svc.assignNode(cfg.id(), "fp-ok", null, "root").block();
            long before = labeler.reconciles.get();

            svc.revokeConfig(cfg.id(), "root", superadmin()).block();
            assertThat(labeler.reconciles.get()).isEqualTo(before + 1);
        }
    }

    @Nested
    class NodeReport {

        @Test
        void appliedReport_flipsTheNodeFedRows_andOnlyThose() {
            EgressVpnService svc = svc(new RecordingSecretWriter(), new CountingLabeler());
            VpnConfig cfgX = svc.importConfig("brandx", "x-cfg", null, WG_X, "rx", "root").block();
            VpnConfig cfgY = svc.importConfig("brandy", "y-cfg", null, WG_Y, "ry", "root").block();
            register("fp-x", "brandx", Device.OWNER_ADMIN);
            register("fp-y", "brandy", Device.OWNER_ADMIN);
            VpnNodeAssignment device = svc.assignNode(cfgX.id(), "fp-x", "coturn", "root").block();
            VpnNodeAssignment domain = svc.assignDomain(cfgX.id(), "brandx", null, "root").block();
            VpnNodeAssignment other = svc.assignNode(cfgY.id(), "fp-y", null, "root").block();

            Long updated = svc.reportNodeState("fp-x", VpnConfig.PROP_APPLIED).block();

            // the DEVICE assignment on fp-x + the DOMAIN assignment on its residency + cfgX.
            assertThat(updated).isEqualTo(3L);
            assertThat(propOfAssignment(device.id())).isEqualTo(VpnConfig.PROP_APPLIED);
            assertThat(propOfAssignment(domain.id())).isEqualTo(VpnConfig.PROP_APPLIED);
            assertThat(propOfConfig(cfgX.id())).isEqualTo(VpnConfig.PROP_APPLIED);
            // the other brand's rows are untouched.
            assertThat(propOfAssignment(other.id())).isEqualTo(VpnConfig.PROP_PENDING);
            assertThat(propOfConfig(cfgY.id())).isEqualTo(VpnConfig.PROP_PENDING);
        }

        @Test
        void failedAndDegradedReports_areRecordedVerbatim() {
            EgressVpnService svc = svc(new RecordingSecretWriter(), new CountingLabeler());
            VpnConfig cfg = svc.importConfig("brandx", "x-cfg", null, WG_X, "rx", "root").block();
            register("fp-x", "brandx", Device.OWNER_ADMIN);
            VpnNodeAssignment a = svc.assignNode(cfg.id(), "fp-x", null, "root").block();

            svc.reportNodeState("fp-x", VpnConfig.PROP_FAILED).block();
            assertThat(propOfAssignment(a.id())).isEqualTo(VpnConfig.PROP_FAILED);

            svc.reportNodeState("fp-x", VpnConfig.PROP_DEGRADED).block();
            assertThat(propOfAssignment(a.id())).isEqualTo(VpnConfig.PROP_DEGRADED);
            assertThat(propOfConfig(cfg.id())).isEqualTo(VpnConfig.PROP_DEGRADED);
        }

        @Test
        void unknownFp_isFailClosedZero_nothingFlips() {
            EgressVpnService svc = svc(new RecordingSecretWriter(), new CountingLabeler());
            VpnConfig cfg = svc.importConfig("brandx", "x-cfg", null, WG_X, "rx", "root").block();
            register("fp-x", "brandx", Device.OWNER_ADMIN);
            VpnNodeAssignment a = svc.assignNode(cfg.id(), "fp-x", null, "root").block();

            Long updated = svc.reportNodeState("fp-ghost", VpnConfig.PROP_APPLIED).block();

            assertThat(updated).isEqualTo(0L);
            assertThat(propOfAssignment(a.id())).isEqualTo(VpnConfig.PROP_PENDING);
            assertThat(propOfConfig(cfg.id())).isEqualTo(VpnConfig.PROP_PENDING);
        }

        @Test
        void superadminOwnedNode_isFailClosedZero() {
            EgressVpnService svc = svc(new RecordingSecretWriter(), new CountingLabeler());
            svc.importConfig("brandx", "x-cfg", null, WG_X, "rx", "root").block();
            register("fp-core", "brandx", Device.OWNER_SUPERADMIN);

            assertThat(svc.reportNodeState("fp-core", VpnConfig.PROP_APPLIED).block()).isEqualTo(0L);
        }

        @Test
        void outOfVocabularyState_throws_forThe422Mapping() {
            EgressVpnService svc = svc(new RecordingSecretWriter(), new CountingLabeler());
            // 'pending' is a MUTATION reset, never a node report; arbitrary strings refused.
            assertThatThrownBy(() -> svc.reportNodeState("fp-x", VpnConfig.PROP_PENDING).block())
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("applied|failed|degraded");
            assertThatThrownBy(() -> svc.reportNodeState("fp-x", "exfiltrated").block())
                    .isInstanceOf(IllegalArgumentException.class);
        }

        @Test
        void revokedConfig_isNotFlippedByAReport() {
            EgressVpnService svc = svc(new RecordingSecretWriter(), new CountingLabeler());
            VpnConfig cfg = svc.importConfig("brandx", "x-cfg", null, WG_X, "rx", "root").block();
            register("fp-x", "brandx", Device.OWNER_ADMIN);
            svc.assignNode(cfg.id(), "fp-x", null, "root").block();
            svc.revokeConfig(cfg.id(), "root", superadmin()).block();

            Long updated = svc.reportNodeState("fp-x", VpnConfig.PROP_APPLIED).block();

            // the cascade already deactivated the assignment, so nothing feeds this node's
            // export any more — the report matches (and flips) nothing.
            assertThat(updated).isEqualTo(0L);
            assertThat(propOfConfig(cfg.id())).isEqualTo(VpnConfig.PROP_PENDING);
        }
    }
}
