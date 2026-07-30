package systems.hugmesh.adminbff.backingservices;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.data.r2dbc.test.autoconfigure.DataR2dbcTest;
import org.springframework.context.annotation.Import;
import org.springframework.r2dbc.core.DatabaseClient;
import org.springframework.test.context.ActiveProfiles;
import systems.hugmesh.adminbff.support.TestDatabaseConfig;
import systems.hugmesh.adminbff.testutil.R2dbcRepos;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The {@code backing_service_mode} R2DBC repository over a Liquibase-applied Postgres
 * (Testcontainers, via {@link TestDatabaseConfig}) — proves the 310 changelog applies (table +
 * the mode CHECK + the read index + the append-only GRANT) and the APPEND-ONLY ledger idioms
 * round-trip: the Persistable-{@code isNew} {@code save()} INSERT, the monotonic generation
 * stamp, and the current-mode-per-service (highest generation) read.
 *
 * <p><b>Harness:</b> {@link TestDatabaseConfig} starts a {@code postgres:16-alpine}
 * Testcontainer — production parity, the same engine the migrated repositories run on — so
 * this suite requires a Docker daemon and runs anywhere one is available (CI or a
 * Docker-enabled dev box), exactly like the sibling {@code cloudbackup} DB suites. The
 * offline-runnable security surface is {@link BackingServiceControllerTest} (a
 * {@code @WebFluxTest}, no DB).
 */
@DataR2dbcTest
@Import(TestDatabaseConfig.class)
@ActiveProfiles("test")
class BackingServiceModeRepositoryTest {

    @Autowired DatabaseClient db;

    @BeforeEach
    void clean() {
        db.sql("DELETE FROM backing_service_mode").fetch().rowsUpdated().block();
    }

    private BackingServiceModeRepository repo() {
        return new BackingServiceModeRepository(
                R2dbcRepos.of(db, BackingServiceModeR2dbcRepository.class));
    }

    // ── append-only ledger: each record is a new row; current mode = highest generation ──
    @Test
    void record_appendsRows_currentModeIsHighestGeneration() {
        BackingServiceModeRepository r = repo();

        BackingServiceMode v1 = r.insertRecorded("postgres-admin-bff",
                BackingServiceMode.MODE_MANAGED, "db.rds.amazonaws.com:5432",
                "hugmesh/postgres-admin-bff", "alice", 1L).block();
        assertThat(v1).isNotNull();
        assertThat(v1.id()).isNotBlank();
        assertThat(v1.managed()).isTrue();
        assertThat(v1.generation()).isEqualTo(1L);

        // A second record for the SAME service APPENDS a new row (never updates) at a higher gen.
        BackingServiceMode v2 = r.insertRecorded("postgres-admin-bff",
                BackingServiceMode.MODE_SELF_HOSTED, null, null, "bob", 2L).block();
        assertThat(v2.id()).isNotEqualTo(v1.id());                 // new row

        // The CURRENT mode is the highest-generation row (self-hosted rollback).
        BackingServiceMode current = r.currentMode("postgres-admin-bff").block();
        assertThat(current.mode()).isEqualTo(BackingServiceMode.MODE_SELF_HOSTED);
        assertThat(current.generation()).isEqualTo(2L);
        // Both rows survive (append-only audit): history has two entries newest-first.
        assertThat(r.history().collectList().block()).hasSize(2);
        assertThat(r.maxGeneration().block()).isEqualTo(2L);
    }

    // ── current-mode-per-service map: one entry per service, its highest generation ──
    @Test
    void currentModes_perService_independentAndLatest() {
        BackingServiceModeRepository r = repo();
        r.insertRecorded("object-store", BackingServiceMode.MODE_MANAGED, "s3://b", null, "a", 1L).block();
        r.insertRecorded("kafka", BackingServiceMode.MODE_MANAGED, "b.msk:9094", null, "a", 2L).block();
        // supersede object-store back to self-hosted at a higher generation.
        r.insertRecorded("object-store", BackingServiceMode.MODE_SELF_HOSTED, null, null, "a", 3L).block();

        Map<String, BackingServiceMode> current = r.currentModes().block();
        assertThat(current).containsOnlyKeys("object-store", "kafka");
        assertThat(current.get("object-store").mode()).isEqualTo(BackingServiceMode.MODE_SELF_HOSTED);
        assertThat(current.get("object-store").generation()).isEqualTo(3L);
        assertThat(current.get("kafka").mode()).isEqualTo(BackingServiceMode.MODE_MANAGED);
        assertThat(current.get("kafka").endpoint()).isEqualTo("b.msk:9094");
    }

    // ── never-recorded service is ABSENT (self-hosted default is filled by the service) ──
    @Test
    void neverRecorded_absentFromCurrentModes() {
        BackingServiceModeRepository r = repo();
        assertThat(r.currentMode("smtp").block()).isNull();
        assertThat(r.currentModes().block()).doesNotContainKey("smtp");
        assertThat(r.maxGeneration().block()).isEqualTo(0L);
    }
}
