package net.hugmesh.adminbff.radio;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.data.r2dbc.test.autoconfigure.DataR2dbcTest;
import org.springframework.context.annotation.Import;
import org.springframework.r2dbc.core.DatabaseClient;
import org.springframework.test.context.ActiveProfiles;
import net.hugmesh.adminbff.support.DeviceRegistryCleanup;
import net.hugmesh.adminbff.support.DeviceRegistryCleanupConfig;
import net.hugmesh.adminbff.support.TestDatabaseConfig;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Proves the {@code 300-node-radio-device.xml} changelog APPLIES over the Liquibase-applied
 * (Testcontainers Postgres) store and that the table shape + CHECK / FK constraints are
 * live. This is the foundation acceptance: the schema exists and is INERT (created empty),
 * and the data-integrity backstops reject malformed rows exactly like the 085 storage
 * tables do — including the PER-TRANSPORT SHAPE CHECK (a mixed serial/tcp/mqtt column set
 * is rejected by the DB even if the service guard were bypassed).
 *
 * <p>Mirrors {@code NodeStorageChangelogTest}'s direct-SQL constraint probes (insert a bad
 * row, expect the DB to reject it via {@code onErrorReturn(-1L)}). The FK from
 * node_radio_device -> device_registry is exercised by inserting against a real registered
 * device row.
 */
@DataR2dbcTest
@Import({TestDatabaseConfig.class, DeviceRegistryCleanupConfig.class})
@ActiveProfiles("test")
class NodeRadioChangelogTest {

    @Autowired DatabaseClient db;

    @Autowired DeviceRegistryCleanup deviceRegistryCleanup;

    @org.junit.jupiter.api.BeforeEach
    void clear() {
        db.sql("DELETE FROM node_radio_device").fetch().rowsUpdated().block();
        deviceRegistryCleanup.clearDeviceRegistry().block();
    }

    @org.junit.jupiter.api.AfterEach
    void cleanup() {
        // FK-safe teardown so the SHARED test context does not leak node_radio_device rows
        // referencing this class's devices into the next @DataR2dbcTest class (whose
        // device_registry cleanup does not clear this child table). Mirrors
        // AdminSshIssuedKeyRepositoryTest's teardown idiom.
        db.sql("DELETE FROM node_radio_device").fetch().rowsUpdated().block();
        deviceRegistryCleanup.clearDeviceRegistry().block();
    }

    /** Register a real device row the radio FK can reference. */
    private void registerDevice(String id, String domain, String ownerType) {
        db.sql("INSERT INTO device_registry "
                        + "(id, machine_key_fp, hostname, image_type, owner_type, physical_owner, "
                        + " domain, mesh_id, created_at) "
                        + "VALUES (:id, :fp, :h, 'mesh-extension', :ot, 'op', :dom, 'mesh-1', now())")
                .bind("id", id).bind("fp", "fp-" + id).bind("h", "node-" + id)
                .bind("ot", ownerType).bind("dom", domain)
                .fetch().rowsUpdated().block();
    }

    /** Attempt a raw radio insert, returning rows-updated or -1 when the DB rejects it. */
    private Long insertRadio(String id, String deviceId, String transport, String serialPath,
                             String host, Integer port, String topicRoot, String channelName,
                             String gatewayNodeId, int meshChannel) {
        var spec = db.sql("INSERT INTO node_radio_device "
                        + "(id, device_id, transport, serial_path, host, port, topic_root, "
                        + " channel_name, gateway_node_id, radio_id, mesh_channel, state, domain, "
                        + " propagation_state, generation, created_by, created_at) "
                        + "VALUES (:id, :dev, :tr, :sp, :h, :p, :root, :cn, :gw, :rid, :mc, "
                        + " 'active', 'brandx', 'pending', 0, 'op', now())")
                .bind("id", id).bind("dev", deviceId).bind("tr", transport)
                .bind("rid", "radio-" + id).bind("mc", meshChannel);
        spec = serialPath == null ? spec.bindNull("sp", String.class) : spec.bind("sp", serialPath);
        spec = host == null ? spec.bindNull("h", String.class) : spec.bind("h", host);
        spec = port == null ? spec.bindNull("p", Integer.class) : spec.bind("p", port);
        spec = topicRoot == null ? spec.bindNull("root", String.class) : spec.bind("root", topicRoot);
        spec = channelName == null ? spec.bindNull("cn", String.class) : spec.bind("cn", channelName);
        spec = gatewayNodeId == null ? spec.bindNull("gw", String.class) : spec.bind("gw", gatewayNodeId);
        return spec.fetch().rowsUpdated().onErrorReturn(-1L).block();
    }

    @Test
    void changelogApplies_tableExistsAndIsEmpty() {
        // The schema is live (a SELECT succeeds) AND the table ships INERT — created empty,
        // so zero radios = today's behaviour exactly.
        Long radios = db.sql("SELECT COUNT(*) AS c FROM node_radio_device")
                .map((r, m) -> r.get("c", Long.class)).first().block();
        assertThat(radios).isZero();
    }

    @Test
    void transportCheck_rejectsUnknownTransport() {
        registerDevice("dev-1", "brandx", "ADMIN");
        assertThat(insertRadio("r1", "dev-1", "bogus", "/dev/ttyUSB0", null, null, null, null,
                null, 0)).isEqualTo(-1L);
    }

    @Test
    void shapeCheck_rejectsMixedSerialAndTcpColumns() {
        // A serial row carrying a host is a MIXED shape — the DB backstop rejects it.
        registerDevice("dev-2", "brandx", "ADMIN");
        assertThat(insertRadio("r2", "dev-2", "serial", "/dev/ttyUSB0", "radio.local", 4403,
                null, null, null, 0)).isEqualTo(-1L);
    }

    @Test
    void shapeCheck_rejectsTcpWithoutHost() {
        registerDevice("dev-3", "brandx", "ADMIN");
        assertThat(insertRadio("r3", "dev-3", "tcp", null, null, 4403, null, null, null, 0))
                .isEqualTo(-1L);
    }

    @Test
    void shapeCheck_rejectsMqttWithoutTopicRoot() {
        registerDevice("dev-3b", "brandx", "ADMIN");
        assertThat(insertRadio("r3b", "dev-3b", "mqtt", null, "mqtt.example.org", 1883, null,
                "LongFast", null, 0)).isEqualTo(-1L);
    }

    @Test
    void shapeCheck_rejectsMqttCarryingSerialPath() {
        registerDevice("dev-3c", "brandx", "ADMIN");
        assertThat(insertRadio("r3c", "dev-3c", "mqtt", "/dev/ttyUSB0", "mqtt.example.org", 1883,
                "msh/US", "LongFast", null, 0)).isEqualTo(-1L);
    }

    @Test
    void meshChannelCheck_rejectsOutOfRange() {
        registerDevice("dev-4", "brandx", "ADMIN");
        assertThat(insertRadio("r4", "dev-4", "serial", "/dev/ttyUSB0", null, null, null, null,
                null, 8)).isEqualTo(-1L);
    }

    @Test
    void portCheck_rejectsOutOfRangePort() {
        registerDevice("dev-5", "brandx", "ADMIN");
        assertThat(insertRadio("r5", "dev-5", "tcp", null, "radio.local", 70000, null, null,
                null, 0)).isEqualTo(-1L);
    }

    @Test
    void deviceFk_rejectsUnknownDevice() {
        // No device row 'ghost' exists — the FK rejects the orphan radio.
        assertThat(insertRadio("r6", "ghost", "serial", "/dev/ttyUSB0", null, null, null, null,
                null, 0)).isEqualTo(-1L);
    }

    @Test
    void happyPath_serialTcpAndMqttShapes_insert() {
        // The three well-formed transport shapes round-trip through the live FKs/CHECKs.
        registerDevice("dev-ok", "brandx", "ADMIN");
        assertThat(insertRadio("r-serial", "dev-ok", "serial", "/dev/ttyUSB0", null, null,
                null, null, null, 0)).isEqualTo(1L);
        assertThat(insertRadio("r-tcp", "dev-ok", "tcp", null, "radio.local", 4403,
                null, null, null, 3)).isEqualTo(1L);
        assertThat(insertRadio("r-mqtt", "dev-ok", "mqtt", null, "mqtt.example.org", 1883,
                "msh/US", "LongFast", "!0a1b2c3d", 7)).isEqualTo(1L);
    }
}
