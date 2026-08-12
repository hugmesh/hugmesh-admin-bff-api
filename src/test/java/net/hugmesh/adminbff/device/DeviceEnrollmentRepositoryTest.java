package net.hugmesh.adminbff.device;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.data.r2dbc.test.autoconfigure.DataR2dbcTest;
import org.springframework.context.annotation.Import;
import org.springframework.r2dbc.core.DatabaseClient;
import org.springframework.test.context.ActiveProfiles;
import net.hugmesh.adminbff.support.TestDatabaseConfig;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * {@link DeviceEnrollmentRepository} over a Liquibase-applied H2 (PG-compat) — proves the 130
 * changelog applies (device_enrollment + UNIQUE) and the findByFp-then-update|insert UPSERT
 * idiom (a re-report bumps count, NEVER violates the UNIQUE). Mirrors
 * {@link DeviceRegistryServiceTest} wiring.
 */
@DataR2dbcTest
@Import(TestDatabaseConfig.class)
@ActiveProfiles("test")
class DeviceEnrollmentRepositoryTest {

    @Autowired DatabaseClient db;

    @org.junit.jupiter.api.BeforeEach
    void clear() {
        db.sql("DELETE FROM device_enrollment").fetch().rowsUpdated().block();
    }

    private DeviceEnrollmentRepository repo() {
        return new DeviceEnrollmentRepository(net.hugmesh.adminbff.testutil.R2dbcRepos.of(db, net.hugmesh.adminbff.device.DeviceEnrollmentRowRepository.class));
    }

    @Test
    void firstReport_inserts_countOne() {
        DeviceEnrollment e = repo().upsert("nodekey:A", "host-a", "mesh-1", "tn-1").block();
        assertThat(e).isNotNull();
        assertThat(e.machineKeyFp()).isEqualTo("nodekey:A");
        assertThat(e.hostname()).isEqualTo("host-a");
        assertThat(e.reportCount()).isEqualTo(1L);
    }

    @Test
    void reReport_upserts_bumpsCount_noUniqueViolation() {
        DeviceEnrollmentRepository repo = repo();
        repo.upsert("nodekey:B", "host-b", "mesh-1", "tn-1").block();
        DeviceEnrollment again = repo.upsert("nodekey:B", "host-b2", "mesh-1", "tn-2").block();
        assertThat(again.reportCount()).isEqualTo(2L);
        assertThat(again.hostname()).isEqualTo("host-b2");   // hints refreshed
        Long count = db.sql("SELECT COUNT(*) AS c FROM device_enrollment WHERE machine_key_fp = 'nodekey:B'")
                .map((r, m) -> r.get("c", Long.class)).first().block();
        assertThat(count).isEqualTo(1L);   // ONE row despite two reports.
    }

    @Test
    void minimalReport_onlyFp_nullHints_ok() {
        DeviceEnrollment e = repo().upsert("nodekey:C", null, null, null).block();
        assertThat(e).isNotNull();
        assertThat(e.hostname()).isNull();
        assertThat(e.reportCount()).isEqualTo(1L);
    }
}
