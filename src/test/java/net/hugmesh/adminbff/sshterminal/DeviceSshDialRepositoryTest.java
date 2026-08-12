package net.hugmesh.adminbff.sshterminal;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.data.r2dbc.test.autoconfigure.DataR2dbcTest;
import org.springframework.context.annotation.Import;
import org.springframework.r2dbc.core.DatabaseClient;
import org.springframework.test.context.ActiveProfiles;
import reactor.test.StepVerifier;
import net.hugmesh.adminbff.support.TestDatabaseConfig;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * {@link DeviceSshDialRepository} over a Liquibase-applied H2 (PG-compat) — proves the 170
 * changelog applies (device_ssh_dial + UNIQUE(device_id) + FK -> device_registry + the status
 * CHECK) and the seed / findByDeviceId / updateStatus idiom round-trips. Mirrors
 * {@link net.hugmesh.adminbff.device.DeviceEnrollmentRepositoryTest} wiring.
 *
 * <p>Per the test-standard: USER-SITUATIONAL (seed/read/status), plus the constraint
 * behaviors (UNIQUE one-row-per-device, FK requires a real device, status CHECK rejects a
 * bad vocabulary).
 */
@DataR2dbcTest
@Import(TestDatabaseConfig.class)
@ActiveProfiles("test")
class DeviceSshDialRepositoryTest {

    @Autowired DatabaseClient db;

    @BeforeEach
    void clean() {
        db.sql("DELETE FROM device_ssh_dial").fetch().rowsUpdated().block();
        db.sql("DELETE FROM device_registry").fetch().rowsUpdated().block();
    }

    private DeviceSshDialRepository repo() {
        return new DeviceSshDialRepository(net.hugmesh.adminbff.testutil.R2dbcRepos.of(db, net.hugmesh.adminbff.sshterminal.DeviceSshDialR2dbcRepository.class));
    }

    /** Seed a parent device_registry row (the FK target) and return its id. */
    private String seedDevice(String id, String fp) {
        db.sql("INSERT INTO device_registry "
                        + "(id, machine_key_fp, hostname, image_type, owner_type, physical_owner, "
                        + " domain, mesh_id, created_at) "
                        + "VALUES (:id, :fp, :host, 'primary', 'ADMIN', 'alice', 'brandx', 'mesh-1', now())")
                .bind("id", id).bind("fp", fp).bind("host", "node-" + id)
                .fetch().rowsUpdated().block();
        return id;
    }

    private DeviceSshDial pending(String deviceId) {
        return new DeviceSshDial(null, deviceId, "snapops", "ssh-ed25519 AAAA...",
                "SHA256:hostfp", "SHA256:dialfp", "vault://kv/dial/" + deviceId,
                "dial-key-" + deviceId, null, DeviceSshDial.STATUS_PENDING, 1L, null, null);
    }

    // ── USER-SITUATIONAL: seed round-trips, lifecycle ─────────────────────────────────────

    @Test
    void insert_roundTrips_pending_noSecretBytes() {
        seedDevice("dev-1", "nodekey:1");
        DeviceSshDial d = repo().insert(pending("dev-1")).block();
        assertThat(d).isNotNull();
        assertThat(d.id()).isNotBlank();
        assertThat(d.status()).isEqualTo(DeviceSshDial.STATUS_PENDING);
        assertThat(d.isActive()).isFalse();
        assertThat(d.generation()).isEqualTo(1L);

        DeviceSshDial read = repo().findByDeviceId("dev-1").block();
        assertThat(read).isNotNull();
        assertThat(read.dialUser()).isEqualTo("snapops");
        assertThat(read.hostKeyFp()).isEqualTo("SHA256:hostfp");
        assertThat(read.dialPubFp()).isEqualTo("SHA256:dialfp");
        assertThat(read.vaultRef()).isEqualTo("vault://kv/dial/dev-1");
        assertThat(read.k8sSecretName()).isEqualTo("dial-key-dev-1");
        assertThat(read.rotatedAt()).isNull();
    }

    @Test
    void findById_resolvesSameRow() {
        seedDevice("dev-1", "nodekey:1");
        DeviceSshDial d = repo().insert(pending("dev-1")).block();
        DeviceSshDial byId = repo().findById(d.id()).block();
        assertThat(byId).isNotNull();
        assertThat(byId.deviceId()).isEqualTo("dev-1");
    }

    @Test
    void updateStatus_pendingToActiveToRevoked_stampsRotatedAt() {
        seedDevice("dev-1", "nodekey:1");
        DeviceSshDial d = repo().insert(pending("dev-1")).block();
        assertThat(repo().updateStatus(d.id(), DeviceSshDial.STATUS_ACTIVE).block()).isEqualTo(1L);
        DeviceSshDial active = repo().findByDeviceId("dev-1").block();
        assertThat(active.status()).isEqualTo(DeviceSshDial.STATUS_ACTIVE);
        assertThat(active.isActive()).isTrue();
        assertThat(active.rotatedAt()).isNotNull();

        assertThat(repo().updateStatus(d.id(), DeviceSshDial.STATUS_REVOKED).block()).isEqualTo(1L);
        assertThat(repo().findByDeviceId("dev-1").block().status())
                .isEqualTo(DeviceSshDial.STATUS_REVOKED);
    }

    @Test
    void updateStatus_absentRow_isNoOp() {
        assertThat(repo().updateStatus("nope", DeviceSshDial.STATUS_ACTIVE).block()).isEqualTo(0L);
    }

    @Test
    void findByDeviceId_absent_empty() {
        StepVerifier.create(repo().findByDeviceId("missing")).verifyComplete();
    }

    // ── CONSTRAINTS: UNIQUE(device_id), FK -> device_registry, status CHECK ────────────────

    @Test
    void uniqueDeviceId_secondRowForSameDevice_rejected() {
        seedDevice("dev-1", "nodekey:1");
        repo().insert(pending("dev-1")).block();
        // a second dial row for the SAME device violates UNIQUE(device_id).
        StepVerifier.create(repo().insert(pending("dev-1")))
                .verifyError();
    }

    @Test
    void fk_dialForUnknownDevice_rejected() {
        // no device_registry row exists for 'ghost' -> the FK rejects the insert.
        StepVerifier.create(repo().insert(pending("ghost")))
                .verifyError();
    }

    @Test
    void statusCheck_rejectsBadVocabulary() {
        seedDevice("dev-1", "nodekey:1");
        DeviceSshDial d = repo().insert(pending("dev-1")).block();
        StepVerifier.create(repo().updateStatus(d.id(), "BOGUS"))
                .verifyError();
    }

    @Test
    void fkCascade_deleteDevice_reapsDialRow() {
        seedDevice("dev-1", "nodekey:1");
        repo().insert(pending("dev-1")).block();
        db.sql("DELETE FROM device_registry WHERE id = 'dev-1'").fetch().rowsUpdated().block();
        StepVerifier.create(repo().findByDeviceId("dev-1")).verifyComplete();
    }
}
