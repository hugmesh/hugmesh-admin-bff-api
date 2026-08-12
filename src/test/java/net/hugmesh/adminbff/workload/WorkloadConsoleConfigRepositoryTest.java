package net.hugmesh.adminbff.workload;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.data.r2dbc.test.autoconfigure.DataR2dbcTest;
import org.springframework.context.annotation.Import;
import org.springframework.r2dbc.core.DatabaseClient;
import org.springframework.test.context.ActiveProfiles;
import net.hugmesh.adminbff.support.TestDatabaseConfig;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The {@code workload_console_config} R2DBC repository over a Liquibase-applied H2. Proves the
 * GLOBAL ' global' sentinel row is SEEDED OFF (ships dark) and the upsert flips both master
 * flags + bumps generation.
 */
@DataR2dbcTest
@Import(TestDatabaseConfig.class)
@ActiveProfiles("test")
class WorkloadConsoleConfigRepositoryTest {

    @Autowired DatabaseClient db;

    private WorkloadConsoleConfigRepository repo() {
        return new WorkloadConsoleConfigRepository(net.hugmesh.adminbff.testutil.R2dbcRepos.of(db, net.hugmesh.adminbff.workload.WorkloadConsoleConfigR2dbcRepository.class));
    }

    @Test
    void globalSentinel_seededOff() {
        WorkloadConsoleConfig global = repo().find(WorkloadConsoleConfig.GLOBAL_DOMAIN).block();
        assertThat(global).isNotNull();
        assertThat(global.adminEnabled()).isFalse();
        assertThat(global.dangerousTierEnabled()).isFalse();
    }

    @Test
    void upsert_insertsThenUpdates_bumpsGeneration() {
        WorkloadConsoleConfigRepository repo = repo();
        WorkloadConsoleConfig inserted = repo.upsert("brandx", true, false, "root", 1).block();
        assertThat(inserted.adminEnabled()).isTrue();
        assertThat(inserted.dangerousTierEnabled()).isFalse();

        WorkloadConsoleConfig updated = repo.upsert("brandx", true, true, "root", 2).block();
        assertThat(updated.dangerousTierEnabled()).isTrue();
        assertThat(updated.generation()).isEqualTo(2);

        // still a single row for the domain
        assertThat(repo.find("brandx").block().dangerousTierEnabled()).isTrue();
    }
}
