package net.hugmesh.adminbff.servicecatalog;

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
 * The {@code app_profile} R2DBC repository over a Liquibase-applied H2 (PG-compat) — proves
 * the 101 changelog applies (table + name UNIQUE) and the GLOBAL profile CRUD round-trips:
 * insert/find/list/update-json/delete + the name UNIQUE backstop.
 */
@DataR2dbcTest
@Import(TestDatabaseConfig.class)
@ActiveProfiles("test")
class AppProfileRepositoryTest {

    @Autowired DatabaseClient db;

    @org.junit.jupiter.api.BeforeEach
    void clear() {
        // The @DataR2dbcTest H2 store is per-CLASS; clear between methods.
        db.sql("DELETE FROM app_profile").fetch().rowsUpdated().block();
    }

    private AppProfileRepository repo() {
        return new AppProfileRepository(net.hugmesh.adminbff.testutil.R2dbcRepos.of(db, net.hugmesh.adminbff.servicecatalog.AppProfileR2dbcRepository.class));
    }

    @Test
    void insert_thenFindByName_roundTripsAndStampsSubject() {
        AppProfileRepository repo = repo();
        AppProfile saved = repo.insert("small-postgres", "{\"cpu\":\"500m\"}", "root@infra").block();
        assertThat(saved).isNotNull();
        assertThat(saved.id()).isNotBlank();
        assertThat(saved.name()).isEqualTo("small-postgres");
        assertThat(saved.createdBySubject()).isEqualTo("root@infra");

        StepVerifier.create(repo.findByName("small-postgres"))
                .assertNext(found -> {
                    assertThat(found.profileJson()).isEqualTo("{\"cpu\":\"500m\"}");
                    assertThat(found.id()).isEqualTo(saved.id());
                })
                .verifyComplete();
    }

    @Test
    void findAll_orderedByName() {
        AppProfileRepository repo = repo();
        repo.insert("zeta", null, "root").block();
        repo.insert("alpha", null, "root").block();
        assertThat(repo.findAll().collectList().block())
                .extracting(AppProfile::name).containsExactly("alpha", "zeta");
    }

    @Test
    void uniqueName_rejectsDuplicateInsert() {
        AppProfileRepository repo = repo();
        repo.insert("dup", null, "root").block();
        StepVerifier.create(repo.insert("dup", "{}", "other")).expectError().verify();
    }

    @Test
    void updateJson_changesJsonOnly_keepsIdAndName() {
        AppProfileRepository repo = repo();
        AppProfile original = repo.insert("p", "{\"v\":1}", "creator").block();
        AppProfile updated = repo.updateJson("p", "{\"v\":2}").block();
        assertThat(updated).isNotNull();
        assertThat(updated.profileJson()).isEqualTo("{\"v\":2}");
        assertThat(updated.id()).isEqualTo(original.id());
        assertThat(updated.name()).isEqualTo("p");
        assertThat(updated.createdBySubject()).isEqualTo("creator");
    }

    @Test
    void updateJson_unknownName_isEmpty() {
        StepVerifier.create(repo().updateJson("ghost", "{}")).verifyComplete();
    }

    @Test
    void deleteByName_removesRow() {
        AppProfileRepository repo = repo();
        repo.insert("temp", null, "root").block();
        assertThat(repo.deleteByName("temp").block()).isEqualTo(1L);
        assertThat(repo.findByName("temp").block()).isNull();
        // A second delete is a no-op.
        assertThat(repo.deleteByName("temp").block()).isEqualTo(0L);
    }
}
