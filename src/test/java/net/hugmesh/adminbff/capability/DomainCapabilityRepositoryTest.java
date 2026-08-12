package net.hugmesh.adminbff.capability;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.data.r2dbc.test.autoconfigure.DataR2dbcTest;
import org.springframework.context.annotation.Import;
import org.springframework.r2dbc.core.DatabaseClient;
import org.springframework.test.context.ActiveProfiles;
import net.hugmesh.adminbff.support.TestDatabaseConfig;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The {@code domain_capability} R2DBC repository over a Liquibase-applied Postgres. Proves
 * the GLOBAL {@code ' global'} sentinel row is SEEDED OFF (ships dark, {@code granted=false})
 * for {@code user-mesh-devices}, and the upsert flips both keys + bumps generation while
 * PRESERVING the composite (domain, capability) identity (a single row per pair, not a
 * duplicate on re-upsert).
 */
@DataR2dbcTest
@Import(TestDatabaseConfig.class)
@ActiveProfiles("test")
class DomainCapabilityRepositoryTest {

    @Autowired DatabaseClient db;

    private DomainCapabilityRepository repo() {
        return new DomainCapabilityRepository(net.hugmesh.adminbff.testutil.R2dbcRepos.of(db,
                DomainCapabilityR2dbcRepository.class));
    }

    @Test
    void globalSentinel_seededOff_forUserMeshDevices() {
        DomainCapability global = repo()
                .find(DomainCapability.GLOBAL_DOMAIN, DomainCapability.USER_MESH_DEVICES).block();
        assertThat(global).isNotNull();
        assertThat(global.granted()).isFalse();
        assertThat(global.enabled()).isFalse();
    }

    @Test
    void unknownDomainCapability_findsEmpty() {
        DomainCapability row = repo().find("brandx", "some-other-capability").block();
        assertThat(row).isNull();
    }

    @Test
    void upsert_insertsThenUpdates_bumpsGeneration_singleRowPerPair() {
        DomainCapabilityRepository repo = repo();
        DomainCapability inserted = repo.upsert("brandx", DomainCapability.USER_MESH_DEVICES,
                true, false, "root", 1).block();
        assertThat(inserted.granted()).isTrue();
        assertThat(inserted.enabled()).isFalse();
        assertThat(inserted.generation()).isEqualTo(1);

        DomainCapability updated = repo.upsert("brandx", DomainCapability.USER_MESH_DEVICES,
                true, true, "admin@brandx", 2).block();
        assertThat(updated.enabled()).isTrue();
        assertThat(updated.generation()).isEqualTo(2);

        // still a single row for the (domain, capability) pair
        DomainCapability current = repo.find("brandx", DomainCapability.USER_MESH_DEVICES).block();
        assertThat(current.granted()).isTrue();
        assertThat(current.enabled()).isTrue();
        assertThat(current.id()).isEqualTo(inserted.id());
    }

    @Test
    void listForDomain_returnsOnlyThatDomainsRows() {
        DomainCapabilityRepository repo = repo();
        repo.upsert("brandx", DomainCapability.USER_MESH_DEVICES, true, true, "root", 1).block();
        repo.upsert("brandy", DomainCapability.USER_MESH_DEVICES, true, false, "root", 2).block();

        var brandxRows = repo.listForDomain("brandx").collectList().block();
        assertThat(brandxRows).hasSize(1);
        assertThat(brandxRows.get(0).domain()).isEqualTo("brandx");
    }

    @Test
    void listAll_includesTheSeededGlobalRow_andEveryDomainRow() {
        DomainCapabilityRepository repo = repo();
        repo.upsert("brandz", DomainCapability.USER_MESH_DEVICES, true, true, "root", 1).block();

        var all = repo.listAll().collectList().block();
        assertThat(all).extracting(DomainCapability::domain)
                .contains(DomainCapability.GLOBAL_DOMAIN, "brandz");
    }
}
