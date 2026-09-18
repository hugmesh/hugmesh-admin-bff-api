package net.hugmesh.adminbff.domainregistry;

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
        return new DomainRegistryRepository(net.hugmesh.adminbff.testutil.R2dbcRepos.of(db, net.hugmesh.adminbff.domainregistry.DomainRegistryRowRepository.class));
    }

    /** A draft registration. The SLUG (nsPrefix, decision 29a) is the brand here, because it
     *  is UNIQUE per domain now (uq_domain_registry_ns_prefix) and every fixture in this class
     *  needs its own. The MCS pair is left UNSET so the repository ALLOCATES it. */
    private static DomainRegistration draft(String clusterDomain, String brand) {
        return new DomainRegistration(null, clusterDomain, brand, "Acme Inc", "vault:pki/acme",
                brand, "acme-org", "tag:acme", true, null, null, null);
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
                    // Decision 29b: idp defaults to the ride-the-superdomain floor.
                    assertThat(found.idp()).isEqualTo(DomainIdp.SUPERDOMAIN);
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
        // Decision 29a: the SLUG is immutable — the merged row asked for "renamed" and the
        // repository carried the stored value through instead. Renaming it would re-point
        // the Vault path secret/<slug>/casdoor at a document that does not exist.
        assertThat(updated.nsPrefix()).isEqualTo("up");
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
    // ── decision 29 (2026-09-17): idp column + writer-allocated MCS pair ──────────────

    @Test
    void insert_allocatesTheMcsPair_fromTheReservedRangeFloor() {
        // DECISION 29c: "the domain_registry writer allocates selinuxLevel / selinuxLevelPg at
        // insert". The FIRST domain in an empty registry takes slot 0 = the range floor, and
        // its Postgres half is the ODD category directly above it (the structural guarantee
        // that the two columns can never collide with each other).
        DomainRegistryRepository repo = repo();
        DomainRegistration saved = repo.insert(draft("mcs.test", "mcs"), "superadmin@infra").block();

        assertThat(saved).isNotNull();
        assertThat(saved.selinuxLevel()).isEqualTo("s0:c" + McsCategoryAllocator.FLOOR_CATEGORY);
        assertThat(saved.selinuxLevelPg())
                .isEqualTo("s0:c" + (McsCategoryAllocator.FLOOR_CATEGORY + 1));

        // and it round-trips through the R2DBC mapping, i.e. the columns really exist.
        StepVerifier.create(repo.findByClusterDomain("mcs.test"))
                .assertNext(found -> {
                    assertThat(found.selinuxLevel()).isEqualTo(saved.selinuxLevel());
                    assertThat(found.selinuxLevelPg()).isEqualTo(saved.selinuxLevelPg());
                })
                .verifyComplete();
    }

    @Test
    void insert_threeDomains_getSixDISTINCTCategories() {
        // docs/SECURITY.md §3: no two WORKLOADS share a category — and every domain is TWO
        // workloads. Three domains must therefore hold six distinct categories, across BOTH
        // columns. A per-column UNIQUE constraint alone would not prove this (it cannot see
        // A.selinux_level == B.selinux_level_pg), which is why the assertion pools them.
        DomainRegistryRepository repo = repo();
        repo.insert(draft("a.test", "a"), "s@infra").block();
        repo.insert(draft("b.test", "b"), "s@infra").block();
        repo.insert(draft("c.test", "c"), "s@infra").block();

        var all = repo.findAll().collectList().block();
        assertThat(all).hasSize(3);
        var categories = all.stream()
                .flatMap(d -> java.util.stream.Stream.of(d.selinuxLevel(), d.selinuxLevelPg()))
                .toList();
        assertThat(categories).hasSize(6).doesNotContainNull().doesNotHaveDuplicates();
    }

    @Test
    void uniqueSelinuxLevel_rejectsASecondRowWithTheSameCategory() {
        // The constraint decision 29c names, proven to EXIST and to BITE. The allocator never
        // produces a duplicate on its own, so the duplicate is forced: a second insert that
        // carries an explicit pair equal to the first row's. Without
        // uq_domain_registry_selinux_level this silently succeeds and two workloads share a
        // category with nothing in the cluster reporting it.
        DomainRegistryRepository repo = repo();
        DomainRegistration first = repo.insert(draft("one.test", "one"), "s@infra").block();
        assertThat(first).isNotNull();

        DomainRegistration collide = new DomainRegistration(
                null, "two.test", "two", "Acme Inc", "vault:pki/acme", "two", "acme-org",
                "tag:acme", true, null, null, null, false, false, 0L,
                DomainIdp.SUPERDOMAIN, first.selinuxLevel(), first.selinuxLevelPg());

        StepVerifier.create(repo.insert(collide, "other@infra"))
                .expectError()
                .verify();
    }

    @Test
    void uniqueSelinuxLevel_bitesONITSOWN_notOnlyViaThePgConstraint() {
        // ISOLATES uq_domain_registry_selinux_level. The test above supplies BOTH halves equal
        // to the first row's, so the _pg constraint alone is enough to reject it — dropping the
        // casdoor-pod constraint left that test GREEN (measured, mutation battery run 1). Here
        // ONLY the casdoor-pod category collides; the Postgres half is a free slot's.
        DomainRegistryRepository repo = repo();
        DomainRegistration first = repo.insert(draft("lvl-a.test", "lvl-a"), "s@infra").block();
        assertThat(first).isNotNull();

        DomainRegistration collide = new DomainRegistration(
                null, "lvl-b.test", "lvl-b", "Acme Inc", "vault:pki/acme", "lvl-b", "acme-org",
                "tag:acme", true, null, null, null, false, false, 0L,
                DomainIdp.SUPERDOMAIN, first.selinuxLevel(), "s0:c1023");

        StepVerifier.create(repo.insert(collide, "other@infra"))
                .expectError()
                .verify();
    }

    @Test
    void uniqueSelinuxLevelPg_bitesONITSOWN() {
        // The mirror image: only the POSTGRES category collides.
        DomainRegistryRepository repo = repo();
        DomainRegistration first = repo.insert(draft("pg-a.test", "pg-a"), "s@infra").block();
        assertThat(first).isNotNull();

        DomainRegistration collide = new DomainRegistration(
                null, "pg-b.test", "pg-b", "Acme Inc", "vault:pki/acme", "pg-b", "acme-org",
                "tag:acme", true, null, null, null, false, false, 0L,
                DomainIdp.SUPERDOMAIN, "s0:c1022", first.selinuxLevelPg());

        StepVerifier.create(repo.insert(collide, "other@infra"))
                .expectError()
                .verify();
    }

    @Test
    void checkConstraint_refusesARowWhoseTwoCategoriesAreTheSame() {
        // ck_domain_registry_selinux_level_distinct. The allocator can never produce this, so
        // the only way in is a hand-written UPDATE — which is exactly what this simulates. A
        // pod and its own database sharing a category is the same §3 violation as two domains
        // sharing one, and nothing in the cluster would report it.
        DomainRegistryRepository repo = repo();
        DomainRegistration row = repo.insert(draft("same.test", "same"), "s@infra").block();
        assertThat(row).isNotNull();

        StepVerifier.create(db.sql("UPDATE domain_registry SET selinux_level_pg = selinux_level "
                        + "WHERE cluster_domain = 'same.test'").fetch().rowsUpdated())
                .expectError()
                .verify();
    }

    @Test
    void checkConstraint_refusesAnUnknownIdp() {
        // ck_domain_registry_idp. The service refuses an unknown idp with a 400; this is the
        // backstop for anything that reaches the table another way.
        DomainRegistryRepository repo = repo();
        repo.insert(draft("idpck.test", "idpck"), "s@infra").block();

        StepVerifier.create(db.sql("UPDATE domain_registry SET idp = 'entra' "
                        + "WHERE cluster_domain = 'idpck.test'").fetch().rowsUpdated())
                .expectError()
                .verify();
    }

    @Test
    void uniqueNsPrefix_rejectsASecondDomainWithTheSameSlug() {
        // DECISION 29a: the slug names the Vault path secret/<slug>/casdoor, so two domains
        // sharing one would read ONE credential document. uq_domain_registry_ns_prefix.
        DomainRegistryRepository repo = repo();
        repo.insert(draft("slug-a.test", "shared"), "s@infra").block();

        DomainRegistration sameSlug = new DomainRegistration(
                null, "slug-b.test", "other", "Acme Inc", "vault:pki/acme", "shared",
                "acme-org", "tag:acme", true, null, null, null);
        StepVerifier.create(repo.insert(sameSlug, "s@infra"))
                .expectError()
                .verify();
    }

    @Test
    void insert_honoursAnExplicitIdp_andUpdateCanFlipIt_butNotTheMcsPair() {
        DomainRegistryRepository repo = repo();
        DomainRegistration own = new DomainRegistration(
                null, "own.test", "own", "Acme Inc", "vault:pki/acme", "own", "acme-org",
                "tag:acme", true, null, null, null, false, false, 0L,
                DomainIdp.OWN, null, null);
        DomainRegistration saved = repo.insert(own, "s@infra").block();
        assertThat(saved).isNotNull();
        assertThat(saved.idp()).isEqualTo(DomainIdp.OWN);
        assertThat(saved.selinuxLevel()).isNotNull();

        // Flip idp back to superdomain AND try to move the categories in the same update.
        DomainRegistration merged = new DomainRegistration(
                saved.id(), "own.test", "own", "Acme Inc", "vault:pki/acme", "own", "acme-org",
                "tag:acme", true, saved.createdAt(), saved.createdBySubject(), saved.updatedAt(),
                false, false, 0L, DomainIdp.SUPERDOMAIN, "s0:c999", "s0:c998");
        DomainRegistration updated = repo.update(merged).block();

        assertThat(updated).isNotNull();
        assertThat(updated.idp()).as("idp IS mutable").isEqualTo(DomainIdp.SUPERDOMAIN);
        assertThat(updated.selinuxLevel())
                .as("the allocated MCS pair is NOT mutable — it belongs to a possibly-running "
                        + "workload, and re-allocating moves its SELinux category underneath it")
                .isEqualTo(saved.selinuxLevel());
        assertThat(updated.selinuxLevelPg()).isEqualTo(saved.selinuxLevelPg());
    }
}
