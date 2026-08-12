package net.hugmesh.adminbff.servicecatalog.scaffold;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.data.r2dbc.test.autoconfigure.DataR2dbcTest;
import org.springframework.context.annotation.Import;
import org.springframework.r2dbc.core.DatabaseClient;
import org.springframework.test.context.ActiveProfiles;
import net.hugmesh.adminbff.support.TestDatabaseConfig;
import net.hugmesh.adminbff.testutil.R2dbcRepos;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The {@code service_scaffold} R2DBC repository over a Liquibase-applied Postgres
 * (Testcontainers, {@link TestDatabaseConfig}) — proves the 320 changelog applies and the
 * scaffold data-layer invariants hold:
 * <ul>
 *   <li>insert stamps a DB-generated id + {@code requested} state (the (gen_random_uuid())::text
 *       + INSERT ... RETURNING id path);</li>
 *   <li>the per-domain read is domain-scoped (brand X never sees brand Y — DENY isolation);</li>
 *   <li>archive is a CAS {@code requested -> archived} (the row stays; a second CAS is a no-op).</li>
 * </ul>
 */
@DataR2dbcTest
@Import(TestDatabaseConfig.class)
@ActiveProfiles("test")
class ServiceScaffoldRepositoryTest {

    @Autowired DatabaseClient db;

    @BeforeEach
    void clear() {
        db.sql("DELETE FROM service_scaffold").fetch().rowsUpdated().block();
    }

    private ServiceScaffoldRepository repo() {
        return new ServiceScaffoldRepository(R2dbcRepos.of(db, ServiceScaffoldR2dbcRepository.class));
    }

    @Test
    void insert_stampsGeneratedIdAndRequestedState_thenFindByIdReadsItBack() {
        ServiceScaffoldRepository repo = repo();
        ServiceScaffold created = repo.insertRequested("brandx", "owncast", "spring-bff", "Owncast",
                "/owncast", "ROLE_OWNCAST", "root").block();

        assertThat(created).isNotNull();
        assertThat(created.id()).isNotBlank();
        assertThat(created.state()).isEqualTo(ServiceScaffold.STATE_REQUESTED);
        assertThat(created.createdAt()).isNotNull();

        ServiceScaffold read = repo.findById(created.id()).block();
        assertThat(read).isNotNull();
        assertThat(read.serviceKey()).isEqualTo("owncast");
        assertThat(read.archetype()).isEqualTo("spring-bff");
        assertThat(read.mountAt()).isEqualTo("/owncast");
        assertThat(read.requiresRole()).isEqualTo("ROLE_OWNCAST");
        assertThat(read.createdBySubject()).isEqualTo("root");
    }

    @Test
    void findByDomain_isDomainScoped_brandXNeverSeesBrandY() {
        ServiceScaffoldRepository repo = repo();
        repo.insertRequested("brandx", "owncast", "spring-bff", null, null, null, "root").block();
        repo.insertRequested("brandx", "wiki", "angular-mfe", null, null, null, "root").block();
        repo.insertRequested("brandy", "forum", "angular-mfe", null, null, null, "root").block();

        List<ServiceScaffold> x = repo.findByDomain("brandx").collectList().block();
        assertThat(x).extracting(ServiceScaffold::serviceKey)
                .containsExactlyInAnyOrder("owncast", "wiki");
        assertThat(x).extracting(ServiceScaffold::domain).containsOnly("brandx");

        List<ServiceScaffold> y = repo.findByDomain("brandy").collectList().block();
        assertThat(y).extracting(ServiceScaffold::serviceKey).containsExactly("forum");
    }

    @Test
    void markArchived_casRequestedToArchived_keepsRow_secondIsNoOp() {
        ServiceScaffoldRepository repo = repo();
        ServiceScaffold created = repo.insertRequested("brandx", "owncast", "spring-bff", null, null,
                null, "root").block();

        Long rows = repo.markArchived(created.id()).block();
        assertThat(rows).isEqualTo(1L);

        ServiceScaffold archived = repo.findById(created.id()).block();
        assertThat(archived).isNotNull();
        assertThat(archived.state()).isEqualTo(ServiceScaffold.STATE_ARCHIVED);

        // The row survives (the audit trail) and a second archive CAS is a no-op (rows == 0).
        assertThat(repo.markArchived(created.id()).block()).isEqualTo(0L);
        assertThat(repo.findByDomain("brandx").collectList().block()).hasSize(1);
    }
}
