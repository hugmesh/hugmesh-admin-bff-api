package systems.hugmesh.adminbff.radio;

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
import systems.hugmesh.adminbff.device.Device;
import systems.hugmesh.adminbff.device.DeviceRegistryRepository;
import systems.hugmesh.adminbff.device.DeviceRegistryService;
import systems.hugmesh.commons.security.DomainRegistry;
import systems.hugmesh.commons.security.PrincipalDomain;
import systems.hugmesh.adminbff.support.TestDatabaseConfig;

import java.time.Instant;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * {@link NodeRadioService} over a Liquibase-applied (Testcontainers Postgres) store. Proves
 * the required acceptance bar for the NODE RADIO control plane:
 * <ul>
 *   <li><b>OWNERSHIP ALLOW/DENY matrix</b> (the load-bearing security): SUPERADMIN
 *       unrestricted; ADMIN allowed ONLY on own-domain ADMIN-owned nodes; ADMIN DENIED a
 *       SUPERADMIN-owned node (403) and DENIED a cross-domain node (403);</li>
 *   <li><b>per-domain isolation</b> on the read surface (a brand-Y admin cannot see a
 *       brand-X radio; SUPERADMIN sees all);</li>
 *   <li><b>per-transport shape matrix</b> (a MIXED serial/tcp/mqtt shape is 422; the tcp
 *       port defaults to the Meshtastic 4403; mqtt requires host+port+topicRoot+channelName
 *       and accepts an optional gatewayNodeId);</li>
 *   <li><b>FIX-NODEFAULT</b> domain stamping from the node's RESIDENCY, never the
 *       caller;</li>
 *   <li><b>idempotent</b> attach + <b>CAS</b> detach (never DELETE = audit).</li>
 * </ul>
 * Mirrors {@code NodeStorageServiceTest} wiring (real repos, JWT-derived
 * {@link PrincipalDomain}).
 */
@DataR2dbcTest
@Import(TestDatabaseConfig.class)
@ActiveProfiles("test")
class NodeRadioServiceTest {

    @Autowired DatabaseClient db;

    @org.junit.jupiter.api.BeforeEach
    void clear() {
        db.sql("DELETE FROM node_radio_device").fetch().rowsUpdated().block();
        db.sql("DELETE FROM device_registry").fetch().rowsUpdated().block();
    }

    @org.junit.jupiter.api.AfterEach
    void cleanup() {
        // FK-safe teardown so the SHARED test context does not leak node_radio_device rows
        // referencing this class's devices into the next @DataR2dbcTest class (whose
        // device_registry cleanup does not clear this child table). Mirrors
        // AdminSshIssuedKeyRepositoryTest's teardown idiom.
        db.sql("DELETE FROM node_radio_device").fetch().rowsUpdated().block();
        db.sql("DELETE FROM device_registry").fetch().rowsUpdated().block();
    }

    private static final DomainRegistry REGISTRY = new DomainRegistry("",
            "https://idp.brandx.example=brandx,https://idp.brandy.example=brandy");
    private static final String BRANDX = "https://idp.brandx.example";
    private static final String BRANDY = "https://idp.brandy.example";

    private DeviceRegistryRepository deviceRepo() { return new DeviceRegistryRepository(systems.hugmesh.adminbff.testutil.R2dbcRepos.of(db, systems.hugmesh.adminbff.device.DeviceRowRepository.class)); }
    private RadioDeviceRepository radioRepo() { return new RadioDeviceRepository(systems.hugmesh.adminbff.testutil.R2dbcRepos.of(db, systems.hugmesh.adminbff.radio.RadioDeviceR2dbcRepository.class)); }
    private NodeRadioService svc() {
        return new NodeRadioService(radioRepo(), deviceRepo());
    }

    /** Register an ADMIN-owned mesh node in a brand. */
    private Device adminNode(String fp, String domain) {
        return register(fp, domain, Device.OWNER_ADMIN, Device.IMAGE_MESH_EXTENSION);
    }

    /** Register a SUPERADMIN-owned (core) node in a brand. */
    private Device superNode(String fp, String domain) {
        return register(fp, domain, Device.OWNER_SUPERADMIN, Device.IMAGE_PRIMARY);
    }

    private Device register(String fp, String domain, String ownerType, String imageType) {
        DeviceRegistryService devSvc = new DeviceRegistryService(deviceRepo(), REGISTRY, false);
        return devSvc.register(new Device(null, fp, "node-" + fp, "tn", imageType, "rpi5",
                ownerType, "owner@" + domain, domain, "mesh-1", null, null)).block();
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

    /** Attach a well-formed serial radio (the happy default for matrix tests). */
    private RadioDevice attachSerial(NodeRadioService svc, String deviceId, String radioId,
                                     PrincipalDomain scope, String by) {
        return svc.attachRadio(deviceId, RadioDevice.TRANSPORT_SERIAL, "/dev/ttyUSB0", null,
                null, null, null, null, radioId, 0, scope, by).block();
    }

    // ════════════════════════ OWNERSHIP ALLOW/DENY ═════════════════════════════
    @Nested
    class OwnershipMatrix {

        @Test
        void admin_ownDomain_adminOwnedNode_isAllowed() {
            // ALLOW: a brandx ADMIN attaches a radio to a brandx ADMIN-owned node.
            NodeRadioService svc = svc();
            Device node = adminNode("fp-ax", "brandx");
            RadioDevice radio = attachSerial(svc, node.id(), "lora-0", admin(BRANDX), "alice@brandx");
            assertThat(radio).isNotNull();
            assertThat(radio.domain()).isEqualTo("brandx");   // FIX-NODEFAULT: from residency
            assertThat(radio.isActive()).isTrue();
        }

        @Test
        void admin_superadminOwnedNode_isDenied403_evenInOwnDomain() {
            // DENY: an ADMIN may NOT touch a SUPERADMIN-owned node, even in their own brand.
            NodeRadioService svc = svc();
            Device core = superNode("fp-core", "brandx");
            assertThatThrownBy(() -> attachSerial(svc, core.id(), "lora-0", admin(BRANDX), "alice@brandx"))
                    .isInstanceOf(RadioAccessDeniedException.class)
                    .hasMessageContaining("SUPERADMIN-owned");

            // No radio row was written for the denied attach.
            Long rows = db.sql("SELECT COUNT(*) AS c FROM node_radio_device WHERE device_id = :d")
                    .bind("d", core.id()).map((r, m) -> r.get("c", Long.class)).first().block();
            assertThat(rows).isZero();
        }

        @Test
        void admin_crossDomainNode_isDenied403() {
            // DENY: a brandx ADMIN may NOT touch a brandy ADMIN-owned node (cross-domain).
            NodeRadioService svc = svc();
            Device brandyNode = adminNode("fp-ay", "brandy");
            assertThatThrownBy(() -> attachSerial(svc, brandyNode.id(), "lora-0", admin(BRANDX), "alice@brandx"))
                    .isInstanceOf(RadioAccessDeniedException.class)
                    .hasMessageContaining("own-domain");
        }

        @Test
        void superadmin_isUnrestricted_anyOwnerAnyDomain() {
            // ALLOW (x3): SUPERADMIN attaches to an ADMIN-owned brandx node, an ADMIN-owned
            // brandy node, AND a SUPERADMIN-owned core node — unrestricted.
            NodeRadioService svc = svc();
            Device ax = adminNode("fp-sx", "brandx");
            Device ay = adminNode("fp-sy", "brandy");
            Device core = superNode("fp-sc", "brandx");

            assertThat(attachSerial(svc, ax.id(), "lora-0", superadmin(), "root")).isNotNull();
            assertThat(attachSerial(svc, ay.id(), "lora-0", superadmin(), "root")).isNotNull();
            assertThat(attachSerial(svc, core.id(), "lora-0", superadmin(), "root")).isNotNull();
        }

        @Test
        void denyReason_purePredicate_coversTheWholeMatrix() {
            // The pure predicate (unit-tested in isolation) IS the matrix.
            Device adminBrandx = new Device("d1", "fp", "h", "tn", Device.IMAGE_MESH_EXTENSION,
                    "rpi5", Device.OWNER_ADMIN, "o", "brandx", "mesh-1", null, null);
            Device superBrandx = new Device("d2", "fp", "h", "tn", Device.IMAGE_PRIMARY,
                    "rpi5", Device.OWNER_SUPERADMIN, "o", "brandx", "mesh-1", null, null);

            // SUPERADMIN: always allowed.
            assertThat(NodeRadioService.denyReason(superadmin(), adminBrandx)).isNull();
            assertThat(NodeRadioService.denyReason(superadmin(), superBrandx)).isNull();
            // ADMIN own-domain admin-owned: allowed.
            assertThat(NodeRadioService.denyReason(admin(BRANDX), adminBrandx)).isNull();
            // ADMIN on superadmin-owned: denied.
            assertThat(NodeRadioService.denyReason(admin(BRANDX), superBrandx)).contains("SUPERADMIN-owned");
            // ADMIN cross-domain: denied.
            assertThat(NodeRadioService.denyReason(admin(BRANDY), adminBrandx)).contains("own-domain");
        }
    }

    // ════════════════════════ per-transport shape matrix ═══════════════════════
    @Nested
    class TransportShapeMatrix {

        @Test
        void serial_requiresSerialPath_andRejectsForeignColumns() {
            NodeRadioService svc = svc();
            Device node = adminNode("fp-sh1", "brandx");
            // Missing serialPath -> 422.
            assertThatThrownBy(() -> svc.attachRadio(node.id(), "serial", null, null, null,
                    null, null, null, "lora-0", 0, admin(BRANDX), "alice@brandx").block())
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("requires serialPath");
            // serial + host is a MIXED shape -> 422.
            assertThatThrownBy(() -> svc.attachRadio(node.id(), "serial", "/dev/ttyUSB0",
                    "radio.local", null, null, null, null, "lora-0", 0,
                    admin(BRANDX), "alice@brandx").block())
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("mixed transport shape");
            // serial + topicRoot is a MIXED shape too -> 422.
            assertThatThrownBy(() -> svc.attachRadio(node.id(), "serial", "/dev/ttyUSB0",
                    null, null, "msh/US", null, null, "lora-0", 0,
                    admin(BRANDX), "alice@brandx").block())
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("mixed transport shape");
        }

        @Test
        void tcp_requiresHost_rejectsForeignColumns_andDefaultsPort4403() {
            NodeRadioService svc = svc();
            Device node = adminNode("fp-sh2", "brandx");
            // Missing host -> 422.
            assertThatThrownBy(() -> svc.attachRadio(node.id(), "tcp", null, null, null,
                    null, null, null, "lora-0", 0, admin(BRANDX), "alice@brandx").block())
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("requires host");
            // tcp + serialPath is a MIXED shape -> 422.
            assertThatThrownBy(() -> svc.attachRadio(node.id(), "tcp", "/dev/ttyUSB0",
                    "radio.local", 4403, null, null, null, "lora-0", 0,
                    admin(BRANDX), "alice@brandx").block())
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("mixed transport shape");
            // tcp + channelName is a MIXED shape -> 422.
            assertThatThrownBy(() -> svc.attachRadio(node.id(), "tcp", null,
                    "radio.local", 4403, null, "LongFast", null, "lora-0", 0,
                    admin(BRANDX), "alice@brandx").block())
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("mixed transport shape");
            // Omitted port defaults to the Meshtastic TCP API port 4403.
            RadioDevice radio = svc.attachRadio(node.id(), "tcp", null, "radio.local", null,
                    null, null, null, "lora-1", 2, admin(BRANDX), "alice@brandx").block();
            assertThat(radio.port()).isEqualTo(4403);
            assertThat(radio.transport()).isEqualTo(RadioDevice.TRANSPORT_TCP);
            assertThat(radio.serialPath()).isNull();
        }

        @Test
        void mqtt_requiresHostPortTopicRootAndChannelName() {
            NodeRadioService svc = svc();
            Device node = adminNode("fp-sh3", "brandx");
            // Missing topicRoot -> 422.
            assertThatThrownBy(() -> svc.attachRadio(node.id(), "mqtt", null, "mqtt.example.org",
                    1883, null, "LongFast", null, "wan-0", 0, admin(BRANDX), "alice@brandx").block())
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("requires topicRoot");
            // Missing channelName -> 422.
            assertThatThrownBy(() -> svc.attachRadio(node.id(), "mqtt", null, "mqtt.example.org",
                    1883, "msh/US", null, null, "wan-0", 0, admin(BRANDX), "alice@brandx").block())
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("requires channelName");
            // Missing port -> 422 (no silent default for a broker).
            assertThatThrownBy(() -> svc.attachRadio(node.id(), "mqtt", null, "mqtt.example.org",
                    null, "msh/US", "LongFast", null, "wan-0", 0, admin(BRANDX), "alice@brandx").block())
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("requires port");
            // mqtt + serialPath is a MIXED shape -> 422.
            assertThatThrownBy(() -> svc.attachRadio(node.id(), "mqtt", "/dev/ttyUSB0",
                    "mqtt.example.org", 1883, "msh/US", "LongFast", null, "wan-0", 0,
                    admin(BRANDX), "alice@brandx").block())
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("mixed transport shape");
        }

        @Test
        void mqtt_happyPath_persistsBrokerShape_gatewayNodeIdOptional() {
            NodeRadioService svc = svc();
            Device node = adminNode("fp-sh4", "brandx");
            // WITHOUT the optional gateway id.
            RadioDevice noGw = svc.attachRadio(node.id(), "mqtt", null, "mqtt.example.org", 1883,
                    "msh/US", "LongFast", null, "wan-0", 1, admin(BRANDX), "alice@brandx").block();
            assertThat(noGw.transport()).isEqualTo(RadioDevice.TRANSPORT_MQTT);
            assertThat(noGw.topicRoot()).isEqualTo("msh/US");
            assertThat(noGw.channelName()).isEqualTo("LongFast");
            assertThat(noGw.gatewayNodeId()).isNull();
            // WITH the optional gateway id (downlink attribution).
            RadioDevice withGw = svc.attachRadio(node.id(), "mqtt", null, "mqtt.example.org", 1883,
                    "msh/US", "LongFast", "!0a1b2c3d", "wan-1", 1, admin(BRANDX), "alice@brandx").block();
            assertThat(withGw.gatewayNodeId()).isEqualTo("!0a1b2c3d");
        }

        @Test
        void unknownTransport_andBadMeshChannel_areRejected422() {
            NodeRadioService svc = svc();
            Device node = adminNode("fp-sh5", "brandx");
            assertThatThrownBy(() -> svc.attachRadio(node.id(), "carrier-pigeon", "/dev/ttyUSB0",
                    null, null, null, null, null, "lora-0", 0, admin(BRANDX), "alice@brandx").block())
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("serial|tcp|mqtt");
            assertThatThrownBy(() -> svc.attachRadio(node.id(), "serial", "/dev/ttyUSB0",
                    null, null, null, null, null, "lora-0", 8, admin(BRANDX), "alice@brandx").block())
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("meshChannel");
        }
    }

    // ════════════════════════ idempotency + CAS ════════════════════════════════
    @Nested
    class IdempotencyAndCas {

        @Test
        void attachRadio_isIdempotent_onActiveDeviceRadioId() {
            NodeRadioService svc = svc();
            Device node = adminNode("fp-idem", "brandx");
            RadioDevice first = attachSerial(svc, node.id(), "lora-dup", admin(BRANDX), "alice@brandx");
            RadioDevice again = attachSerial(svc, node.id(), "lora-dup", admin(BRANDX), "alice@brandx");
            assertThat(again.id()).isEqualTo(first.id());
            Long count = db.sql("SELECT COUNT(*) AS c FROM node_radio_device "
                            + "WHERE device_id = :d AND radio_id = 'lora-dup' AND state = 'active'")
                    .bind("d", node.id()).map((r, m) -> r.get("c", Long.class)).first().block();
            assertThat(count).isEqualTo(1L);
        }

        @Test
        void detachRadio_isCas_winnerThenNoop_neverDeletes_bumpsGeneration() {
            NodeRadioService svc = svc();
            Device node = adminNode("fp-det", "brandx");
            RadioDevice radio = attachSerial(svc, node.id(), "lora-0", admin(BRANDX), "alice@brandx");
            long genBefore = radio.generation();

            assertThat(svc.detachRadio(radio.id(), admin(BRANDX), "alice@brandx").block()).isEqualTo(1L);
            assertThat(svc.detachRadio(radio.id(), admin(BRANDX), "alice@brandx").block()).isEqualTo(0L);

            RadioDevice after = radioRepo().findById(radio.id()).block();
            assertThat(after).isNotNull();
            assertThat(after.state()).isEqualTo(RadioDevice.STATE_DETACHED);
            assertThat(after.detachedBy()).isEqualTo("alice@brandx");
            assertThat(after.generation()).isGreaterThan(genBefore);
            assertThat(after.propagationState()).isEqualTo(RadioDevice.PROP_PENDING);
        }

        @Test
        void detach_onCrossDomainRadio_isDenied403() {
            // The ownership gate fires on the radio's NODE for detach too — a brandx admin
            // cannot detach a radio pinned to a brandy node.
            NodeRadioService svc = svc();
            Device brandyNode = adminNode("fp-y2", "brandy");
            RadioDevice radio = attachSerial(svc, brandyNode.id(), "lora-0", superadmin(), "root");
            assertThatThrownBy(() -> svc.detachRadio(radio.id(), admin(BRANDX), "alice@brandx").block())
                    .isInstanceOf(RadioAccessDeniedException.class);
        }
    }

    // ════════════════════════ per-domain isolation ═════════════════════════════
    @Nested
    class TenantIsolation {

        @Test
        void admin_readsOwnDomainOnly_crossDomainEmpty_superadminSeesAll() {
            NodeRadioService svc = svc();
            Device nx = adminNode("fp-tx", "brandx");
            Device ny = adminNode("fp-ty", "brandy");
            // superadmin attaches a radio in each brand.
            attachSerial(svc, nx.id(), "lora-x", superadmin(), "root");
            attachSerial(svc, ny.id(), "lora-y", superadmin(), "root");

            // brandx admin sees ONLY the brandx radio.
            assertThat(svc.listRadios(admin(BRANDX)).collectList().block())
                    .extracting(RadioDevice::radioId).containsExactly("lora-x");

            // brandy admin sees ONLY brandy — the brandx row is invisible (cross-domain DENY).
            assertThat(svc.listRadios(admin(BRANDY)).collectList().block())
                    .extracting(RadioDevice::radioId).containsExactly("lora-y");

            // SUPERADMIN (unscoped) sees both.
            assertThat(svc.listRadios(superadmin()).collectList().block())
                    .extracting(RadioDevice::radioId)
                    .containsExactlyInAnyOrder("lora-x", "lora-y");
        }
    }

    // ════════════════════════ unknown node / validation ════════════════════════
    @Nested
    class Validation {

        @Test
        void attach_onUnregisteredNode_isRejected422() {
            assertThatThrownBy(() -> attachSerial(svc(), "no-such-node", "lora-0", superadmin(), "root"))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("not registered");
        }

        @Test
        void detach_unknownRadio_isRejected422() {
            NodeRadioService svc = svc();
            assertThatThrownBy(() -> svc.detachRadio("no-such-radio", superadmin(), "root").block())
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("not found");
        }
    }
}
