package net.hugmesh.adminbff.domainregistry;

import net.hugmesh.adminbff.support.TestDatabaseConfig;
import net.hugmesh.adminbff.testutil.R2dbcRepos;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.data.r2dbc.test.autoconfigure.DataR2dbcTest;
import org.springframework.context.annotation.Import;
import org.springframework.r2dbc.core.DatabaseClient;
import org.springframework.test.context.ActiveProfiles;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The CA effector's database surface (hugmesh-admin-bff-api#99) over the Liquibase-applied
 * Postgres: the pending-row finder and the compare-and-set write of {@code ca_ref} +
 * {@code ca_provisioned} (band 190). Same {@code @DataR2dbcTest} shape as
 * {@link DomainRegistryRepositoryTest}.
 */
@DataR2dbcTest
@Import(TestDatabaseConfig.class)
@ActiveProfiles("test")
class DomainCaRepositoryTest {

    @Autowired DatabaseClient db;

    @BeforeEach
    void clean() {
        db.sql("DELETE FROM domain_registry").fetch().rowsUpdated().block();
    }

    private DomainRegistryRepository repo() {
        return new DomainRegistryRepository(R2dbcRepos.of(db, DomainRegistryRowRepository.class));
    }

    private static DomainRegistration draft(String clusterDomain, String slug, String caRef) {
        return new DomainRegistration(null, clusterDomain, slug, "Org", caRef, slug,
                slug + "-org", "tag:" + slug, true, null, null, null);
    }

    @Test
    void findCaPendingGenerate_returnsOnlyUnprovisionedGenerateRows() {
        DomainRegistryRepository repo = repo();
        repo.insert(draft("beta.test", "beta", "generate"), "su").block();
        repo.insert(draft("alpha.test", "alpha", "generate"), "su").block();
        repo.insert(draft("ext.test", "ext", "vault:pki/ext"), "su").block();
        repo.insert(draft("none.test", "none", null), "su").block();

        assertThat(repo.findCaPendingGenerate().collectList().block())
                .extracting(DomainRegistration::clusterDomain)
                .containsExactly("alpha.test", "beta.test");
    }

    @Test
    void markCaProvisioned_writesTheCaRefAndTheFlag_andDropsTheRowFromTheWorkList() {
        DomainRegistryRepository repo = repo();
        DomainRegistration saved = repo.insert(draft("acme.test", "acme", "generate"), "su").block();
        assertThat(saved).isNotNull();
        assertThat(saved.caProvisioned()).isFalse();

        assertThat(repo.markCaProvisioned(saved.id(), "pki-domain-acme").block()).isTrue();

        DomainRegistration after = repo.findByClusterDomain("acme.test").block();
        assertThat(after).isNotNull();
        assertThat(after.caRef()).isEqualTo("pki-domain-acme");
        assertThat(after.caProvisioned()).isTrue();
        // The rest of the row is untouched.
        assertThat(after.appsetRegistered()).isFalse();
        assertThat(after.brand()).isEqualTo("acme");
        assertThat(after.selinuxLevel()).isEqualTo(saved.selinuxLevel());
        assertThat(repo.findCaPendingGenerate().collectList().block()).isEmpty();
    }

    @Test
    void markCaProvisioned_isCompareAndSet_secondCallChangesNothing() {
        DomainRegistryRepository repo = repo();
        DomainRegistration saved = repo.insert(draft("acme.test", "acme", "generate"), "su").block();

        assertThat(repo.markCaProvisioned(saved.id(), "pki-domain-acme").block()).isTrue();
        assertThat(repo.markCaProvisioned(saved.id(), "pki-domain-other").block()).isFalse();

        assertThat(repo.findByClusterDomain("acme.test").block().caRef()).isEqualTo("pki-domain-acme");
    }

    @Test
    void markCaProvisioned_neverOverwritesARowThatWasRePointed() {
        DomainRegistryRepository repo = repo();
        DomainRegistration saved = repo.insert(draft("acme.test", "acme", "generate"), "su").block();
        // A SUPERADMIN re-points ca_ref while the effector is talking to Vault.
        repo.update(draft("acme.test", "acme", "vault:pki/imported")).block();

        assertThat(repo.markCaProvisioned(saved.id(), "pki-domain-acme").block()).isFalse();

        DomainRegistration after = repo.findByClusterDomain("acme.test").block();
        assertThat(after.caRef()).isEqualTo("vault:pki/imported");
        assertThat(after.caProvisioned()).isFalse();
    }

    @Test
    void crudUpdate_preservesTheProvisionedFlagTheEffectorWrote() {
        DomainRegistryRepository repo = repo();
        DomainRegistration saved = repo.insert(draft("acme.test", "acme", "generate"), "su").block();
        repo.markCaProvisioned(saved.id(), "pki-domain-acme").block();

        DomainRegistration patched = new DomainRegistration(null, "acme.test", "acme-renamed", "Org",
                "pki-domain-acme", "acme", "acme-org", "tag:acme", true, null, null, null);
        repo.update(patched).block();

        DomainRegistration after = repo.findByClusterDomain("acme.test").block();
        assertThat(after.brand()).isEqualTo("acme-renamed");
        assertThat(after.caProvisioned()).isTrue();
    }
}
