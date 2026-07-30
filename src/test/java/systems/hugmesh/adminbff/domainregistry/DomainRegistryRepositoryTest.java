package systems.hugmesh.adminbff.domainregistry;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.data.r2dbc.test.autoconfigure.DataR2dbcTest;
import org.springframework.context.annotation.Import;
import org.springframework.r2dbc.core.DatabaseClient;
import org.springframework.test.context.ActiveProfiles;
import reactor.test.StepVerifier;
import systems.hugmesh.adminbff.support.TestDatabaseConfig;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The domain_registry R2DBC repository over a Liquibase-applied H2 (PG-compat) — proves
 * the 012 changelog applies (table + UNIQUE) and the registry read/write/update
 * round-trips. Uses {@code @DataR2dbcTest} (like {@code DeviceRegistryServiceTest})
 * rather than a nested {@code @SpringBootConfiguration} Boot class, so it does NOT
 * shadow {@code AdminBffApplication} as the package's component-scan root for the
 * co-located {@code DomainRegistryControllerTest} {@code @WebFluxTest} slice.
 */
@DataR2dbcTest
@Import(TestDatabaseConfig.class)
@ActiveProfiles("test")
class DomainRegistryRepositoryTest {

    @Autowired DatabaseClient db;

    /** The per-context Postgres database is shared across this class's methods (no per-method
     *  rollback under {@code @DataR2dbcTest} for R2DBC); clear the table before each test so the
     *  {@code findAll}/order assertions see ONLY their own rows — mirrors the
     *  {@code DeviceRegistryServiceTest} DELETE-FROM cleanup idiom. */
    @BeforeEach
    void clean() {
        db.sql("DELETE FROM domain_registry").fetch().rowsUpdated().block();
    }

    private DomainRegistryRepository repo() {
        return new DomainRegistryRepository(systems.hugmesh.adminbff.testutil.R2dbcRepos.of(db, systems.hugmesh.adminbff.domainregistry.DomainRegistryRowRepository.class));
    }

    private static DomainRegistration draft(String clusterDomain, String brand) {
        return new DomainRegistration(null, clusterDomain, brand, "Acme Inc", "vault:pki/acme",
                "acme", "acme-org", "tag:acme", true, null, null, null);
    }

    @Test
    void insert_thenFindByClusterDomain_roundTripsAndStampsSubject() {
        DomainRegistryRepository repo = repo();
        DomainRegistration saved = repo.insert(draft("acme.test", "acme"), "superadmin@infra").block();
        assertThat(saved).isNotNull();
        assertThat(saved.id()).isNotBlank();
        assertThat(saved.clusterDomain()).isEqualTo("acme.test");
        assertThat(saved.enabled()).isTrue();
        assertThat(saved.createdBySubject()).isEqualTo("superadmin@infra");

        StepVerifier.create(repo.findByClusterDomain("acme.test"))
                .assertNext(found -> {
                    assertThat(found.brand()).isEqualTo("acme");
                    assertThat(found.org()).isEqualTo("Acme Inc");
                    assertThat(found.caRef()).isEqualTo("vault:pki/acme");
                    assertThat(found.nsPrefix()).isEqualTo("acme");
                    assertThat(found.casdoorOrg()).isEqualTo("acme-org");
                    assertThat(found.meshTag()).isEqualTo("tag:acme");
                    assertThat(found.createdBySubject()).isEqualTo("superadmin@infra");
                    assertThat(found.id()).isEqualTo(saved.id());
                })
                .verifyComplete();
    }

    @Test
    void findAll_returnsEveryDomain_orderedByClusterDomain() {
        DomainRegistryRepository repo = repo();
        repo.insert(draft("beta.test", "beta"), "superadmin@infra").block();
        repo.insert(draft("alpha.test", "alpha"), "superadmin@infra").block();

        var all = repo.findAll().collectList().block();
        assertThat(all).extracting(DomainRegistration::clusterDomain)
                .containsExactly("alpha.test", "beta.test");
    }

    @Test
    void uniqueClusterDomain_rejectsDuplicateInsert() {
        DomainRegistryRepository repo = repo();
        repo.insert(draft("dup.test", "dup"), "superadmin@infra").block();
        // The cluster_domain UNIQUE index (uq_domain_registry_cluster_domain) rejects a
        // second row with the same natural key — the DB backstop behind the service's
        // find-before-insert 409.
        StepVerifier.create(repo.insert(draft("dup.test", "dup2"), "other@infra"))
                .expectError()
                .verify();
    }

    @Test
    void update_changesMutableFields_butNotIdOrClusterDomainOrCreatedBy() {
        DomainRegistryRepository repo = repo();
        DomainRegistration original = repo.insert(draft("up.test", "up"), "creator@infra").block();

        // A full merged row (the service computes this); flip enabled + change brand/org.
        DomainRegistration merged = new DomainRegistration(
                original.id(), "up.test", "renamed", "Renamed LLC", "vault:pki/renamed",
                "renamed", "renamed-org", "tag:renamed", false,
                original.createdAt(), original.createdBySubject(), original.updatedAt());

        DomainRegistration updated = repo.update(merged).block();
        assertThat(updated).isNotNull();
        // Mutable fields changed.
        assertThat(updated.brand()).isEqualTo("renamed");
        assertThat(updated.org()).isEqualTo("Renamed LLC");
        assertThat(updated.enabled()).isFalse();
        // PK + natural key + provenance UNCHANGED.
        assertThat(updated.id()).isEqualTo(original.id());
        assertThat(updated.clusterDomain()).isEqualTo("up.test");
        assertThat(updated.createdBySubject()).isEqualTo("creator@infra");
    }

    @Test
    void update_unknownClusterDomain_isEmpty() {
        DomainRegistryRepository repo = repo();
        StepVerifier.create(repo.update(draft("ghost.test", "ghost")))
                .verifyComplete(); // no row updated -> empty
    }

    // ── band-190 provisioning-status columns (default false/false/0; ships dark) ──

    @Test
    void insert_provisioningStatusFields_defaultToUnprovisionedFloor() {
        // The CRUD insert never sets the status fields; the DB DEFAULT false/false/0 floor
        // round-trips back through the R2DBC mapping. Proves the band-190 columns exist + map.
        DomainRegistryRepository repo = repo();
        repo.insert(draft("prov.test", "prov"), "superadmin@infra").block();

        StepVerifier.create(repo.findByClusterDomain("prov.test"))
                .assertNext(found -> {
                    assertThat(found.caProvisioned()).isFalse();
                    assertThat(found.appsetRegistered()).isFalse();
                    assertThat(found.lastReconciledGeneration()).isEqualTo(0L);
                })
                .verifyComplete();
    }

    @Test
    void update_preservesProvisioningStatus_crudNeverClobbersIt() {
        // A SUPERADMIN soft-disable/rename must NOT reset the effector-owned status fields.
        // Seed a row whose status the (later) effector would have flipped, then run the CRUD
        // update and assert the status survives (the repo carries it through from the existing
        // row rather than the false/false/0 default).
        DomainRegistryRepository repo = repo();
        // Insert at the floor, then directly bump the status columns (simulating the effector).
        DomainRegistration seeded = repo.insert(draft("keep.test", "keep"), "creator@infra").block();
        db.sql("UPDATE domain_registry SET ca_provisioned = true, appset_registered = true, "
                        + "last_reconciled_generation = 7 WHERE cluster_domain = 'keep.test'")
                .fetch().rowsUpdated().block();

        // A CRUD update (rename + soft-disable) — must preserve the provisioning status.
        DomainRegistration merged = new DomainRegistration(
                seeded.id(), "keep.test", "renamed", "Renamed", "vault:pki/renamed",
                "renamed", "renamed-org", "tag:renamed", false,
                seeded.createdAt(), seeded.createdBySubject(), seeded.updatedAt());
        DomainRegistration updated = repo.update(merged).block();

        assertThat(updated).isNotNull();
        assertThat(updated.brand()).isEqualTo("renamed");       // mutable field changed
        assertThat(updated.enabled()).isFalse();                // soft-disable applied
        assertThat(updated.caProvisioned()).isTrue();           // status PRESERVED
        assertThat(updated.appsetRegistered()).isTrue();        // status PRESERVED
        assertThat(updated.lastReconciledGeneration()).isEqualTo(7L); // status PRESERVED
    }
}
