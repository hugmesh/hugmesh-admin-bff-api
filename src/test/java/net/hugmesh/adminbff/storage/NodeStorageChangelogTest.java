package net.hugmesh.adminbff.storage;

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
 * Proves the {@code 085-node-storage.xml} changelog APPLIES over a Liquibase-applied H2
 * (PG-compat) store and that the table shapes + CHECK / FK constraints are live. This is the
 * PR1 (foundation) acceptance: the schema exists and is INERT (created empty), and the
 * data-integrity backstops reject malformed rows exactly like the 011 device tables do.
 *
 * <p>Mirrors {@code DeviceRegistryServiceTest}'s direct-SQL constraint probes (insert a bad
 * row, expect the DB to reject it via {@code onErrorReturn(-1L)}). The FK from
 * node_storage_pool -> device_registry and storage_service_assignment -> node_storage_pool
 * is exercised by inserting against a real registered device row.
 */
@DataR2dbcTest
@Import({TestDatabaseConfig.class, DeviceRegistryCleanupConfig.class})
@ActiveProfiles("test")
class NodeStorageChangelogTest {

    @Autowired DatabaseClient db;

    @Autowired DeviceRegistryCleanup deviceRegistryCleanup;

    @org.junit.jupiter.api.BeforeEach
    void clear() {
        db.sql("DELETE FROM storage_service_assignment").fetch().rowsUpdated().block();
        db.sql("DELETE FROM node_storage_pool").fetch().rowsUpdated().block();
        deviceRegistryCleanup.clearDeviceRegistry().block();
    }

    /** Register a real device row the pool FK can reference. */
    private void registerDevice(String id, String domain, String ownerType) {
        db.sql("INSERT INTO device_registry "
                        + "(id, machine_key_fp, hostname, image_type, owner_type, physical_owner, "
                        + " domain, mesh_id, created_at) "
                        + "VALUES (:id, :fp, :h, 'mesh-extension', :ot, 'op', :dom, 'mesh-1', now())")
                .bind("id", id).bind("fp", "fp-" + id).bind("h", "node-" + id)
                .bind("ot", ownerType).bind("dom", domain)
                .fetch().rowsUpdated().block();
    }

    private void insertPool(String id, String deviceId, String state, long reservedBytes, String domain) {
        db.sql("INSERT INTO node_storage_pool "
                        + "(id, device_id, disk_serial, pool_path, reserved_bytes, state, domain, "
                        + " propagation_state, generation, created_by, created_at) "
                        + "VALUES (:id, :dev, :ser, :path, :rb, :st, :dom, 'pending', 0, 'op', now())")
                .bind("id", id).bind("dev", deviceId).bind("ser", "ser-" + id)
                .bind("path", "/var/hugmesh/storage/" + id).bind("rb", reservedBytes)
                .bind("st", state).bind("dom", domain)
                .fetch().rowsUpdated().block();
    }

    @Test
    void changelogApplies_bothTablesExistAndAreEmpty() {
        // The schema is live (a SELECT against each table succeeds) AND the tables ship
        // INERT — created empty, so zero pools = today's behaviour exactly.
        Long pools = db.sql("SELECT COUNT(*) AS c FROM node_storage_pool")
                .map((r, m) -> r.get("c", Long.class)).first().block();
        Long assigns = db.sql("SELECT COUNT(*) AS c FROM storage_service_assignment")
                .map((r, m) -> r.get("c", Long.class)).first().block();
        assertThat(pools).isZero();
        assertThat(assigns).isZero();
    }

    @Test
    void pool_stateCheck_rejectsUnknownState() {
        registerDevice("dev-1", "brandx", "ADMIN");
        Long updated = db.sql("INSERT INTO node_storage_pool "
                        + "(id, device_id, disk_serial, pool_path, reserved_bytes, state, domain, "
                        + " propagation_state, generation, created_by, created_at) "
                        + "VALUES ('p', 'dev-1', 's', '/p', 100, 'bogus', 'brandx', 'pending', 0, 'op', now())")
                .fetch().rowsUpdated().onErrorReturn(-1L).block();
        assertThat(updated).isEqualTo(-1L);
    }

    @Test
    void pool_reservedBytesCheck_rejectsNonPositive() {
        registerDevice("dev-2", "brandx", "ADMIN");
        Long updated = db.sql("INSERT INTO node_storage_pool "
                        + "(id, device_id, disk_serial, pool_path, reserved_bytes, state, domain, "
                        + " propagation_state, generation, created_by, created_at) "
                        + "VALUES ('p2', 'dev-2', 's', '/p', 0, 'active', 'brandx', 'pending', 0, 'op', now())")
                .fetch().rowsUpdated().onErrorReturn(-1L).block();
        assertThat(updated).isEqualTo(-1L);
    }

    @Test
    void pool_deviceFk_rejectsUnknownDevice() {
        // No device row 'ghost' exists — the FK rejects the orphan pool.
        Long updated = db.sql("INSERT INTO node_storage_pool "
                        + "(id, device_id, disk_serial, pool_path, reserved_bytes, state, domain, "
                        + " propagation_state, generation, created_by, created_at) "
                        + "VALUES ('p3', 'ghost', 's', '/p', 100, 'active', 'brandx', 'pending', 0, 'op', now())")
                .fetch().rowsUpdated().onErrorReturn(-1L).block();
        assertThat(updated).isEqualTo(-1L);
    }

    @Test
    void pool_propagationCheck_rejectsUnknownPropagationState() {
        registerDevice("dev-3", "brandx", "ADMIN");
        Long updated = db.sql("INSERT INTO node_storage_pool "
                        + "(id, device_id, disk_serial, pool_path, reserved_bytes, state, domain, "
                        + " propagation_state, generation, created_by, created_at) "
                        + "VALUES ('p4', 'dev-3', 's', '/p', 100, 'active', 'brandx', 'limbo', 0, 'op', now())")
                .fetch().rowsUpdated().onErrorReturn(-1L).block();
        assertThat(updated).isEqualTo(-1L);
    }

    @Test
    void assignment_stateCheck_rejectsUnknownState() {
        registerDevice("dev-4", "brandx", "ADMIN");
        insertPool("pool-4", "dev-4", "active", 1000, "brandx");
        Long updated = db.sql("INSERT INTO storage_service_assignment "
                        + "(id, pool_id, service_name, pvc_name, requested_bytes, state, assigned_by, "
                        + " assigned_at, domain, propagation_state, generation) "
                        + "VALUES ('a', 'pool-4', 'svc', 'pvc', 100, 'bogus', 'op', now(), 'brandx', 'pending', 0)")
                .fetch().rowsUpdated().onErrorReturn(-1L).block();
        assertThat(updated).isEqualTo(-1L);
    }

    @Test
    void assignment_poolFk_rejectsUnknownPool() {
        Long updated = db.sql("INSERT INTO storage_service_assignment "
                        + "(id, pool_id, service_name, pvc_name, requested_bytes, state, assigned_by, "
                        + " assigned_at, domain, propagation_state, generation) "
                        + "VALUES ('a2', 'no-pool', 'svc', 'pvc', 100, 'active', 'op', now(), 'brandx', 'pending', 0)")
                .fetch().rowsUpdated().onErrorReturn(-1L).block();
        assertThat(updated).isEqualTo(-1L);
    }

    @Test
    void assignment_requestedBytesCheck_rejectsNonPositive() {
        registerDevice("dev-5", "brandx", "ADMIN");
        insertPool("pool-5", "dev-5", "active", 1000, "brandx");
        Long updated = db.sql("INSERT INTO storage_service_assignment "
                        + "(id, pool_id, service_name, pvc_name, requested_bytes, state, assigned_by, "
                        + " assigned_at, domain, propagation_state, generation) "
                        + "VALUES ('a3', 'pool-5', 'svc', 'pvc', -1, 'active', 'op', now(), 'brandx', 'pending', 0)")
                .fetch().rowsUpdated().onErrorReturn(-1L).block();
        assertThat(updated).isEqualTo(-1L);
    }

    @Test
    void happyPath_poolThenAssignment_inserts() {
        // The well-formed pool + assignment round-trips through the live FKs/CHECKs.
        registerDevice("dev-ok", "brandx", "ADMIN");
        insertPool("pool-ok", "dev-ok", "active", 5000, "brandx");
        Long updated = db.sql("INSERT INTO storage_service_assignment "
                        + "(id, pool_id, service_name, pvc_name, requested_bytes, state, assigned_by, "
                        + " assigned_at, domain, propagation_state, generation) "
                        + "VALUES ('a-ok', 'pool-ok', 'owncast', 'owncast-data', 1000, 'active', 'op', "
                        + " now(), 'brandx', 'pending', 0)")
                .fetch().rowsUpdated().onErrorReturn(-1L).block();
        assertThat(updated).isEqualTo(1L);
    }
}
