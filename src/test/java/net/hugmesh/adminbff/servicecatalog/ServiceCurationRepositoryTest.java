package net.hugmesh.adminbff.servicecatalog;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.data.r2dbc.test.autoconfigure.DataR2dbcTest;
import org.springframework.context.annotation.Import;
import org.springframework.r2dbc.core.DatabaseClient;
import org.springframework.test.context.ActiveProfiles;
import net.hugmesh.commons.security.DomainRegistry;
import net.hugmesh.commons.security.PrincipalDomain;
import net.hugmesh.adminbff.support.TestDatabaseConfig;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The {@code service_curation} R2DBC repository over a Liquibase-applied H2 (PG-compat) —
 * proves the 100 changelog applies and the TWO-TIER curation isolation holds:
 * <ul>
 *   <li>the SUPERADMIN write surface targets an explicit domain;</li>
 *   <li>the ADMIN read surface ({@link ServiceCurationRepository#offeredForScope}) returns
 *       ONLY the caller's-domain offered rows — brand X never sees brand Y, tested with two
 *       domains (DENY isolation);</li>
 *   <li>a withdraw is a CAS offered->withdrawn (the row stays; the admin no longer sees it);</li>
 *   <li>SUPERADMIN scope is UNSCOPED (sees both brands' offered rows).</li>
 * </ul>
 */
@DataR2dbcTest
@Import(TestDatabaseConfig.class)
@ActiveProfiles("test")
class ServiceCurationRepositoryTest {

    @Autowired DatabaseClient db;

    @org.junit.jupiter.api.BeforeEach
    void clear() {
        // The @DataR2dbcTest H2 store is per-CLASS (not per-method); clear so rows from a
        // prior test method do not leak into this one (the SuspensionServiceDomainScopeTest
        // convention).
        db.sql("DELETE FROM service_curation").fetch().rowsUpdated().block();
    }

    private ServiceCurationRepository repo() {
        return new ServiceCurationRepository(net.hugmesh.adminbff.testutil.R2dbcRepos.of(db, net.hugmesh.adminbff.servicecatalog.ServiceCurationR2dbcRepository.class));
    }

    private static final DomainRegistry REGISTRY = new DomainRegistry("",
            "https://idp.brandx.example=brandx,https://idp.brandy.example=brandy");

    private static PrincipalDomain scoped(String domain) {
        // Build a SCOPED PrincipalDomain by reflection-free construction via the issuer path is
        // overkill here; the repository only reads scope.scoped()/scope.domain(), so use the
        // public factory with a synthetic admin auth.
        return ScopeFixtures.admin(domain, REGISTRY);
    }

    private static PrincipalDomain superadminScope() {
        return ScopeFixtures.superadmin(REGISTRY);
    }

    @Test
    void offer_thenAdminReadOwnDomain_seesOnlyTheirOfferedRows() {
        ServiceCurationRepository repo = repo();
        repo.insertOffered("brandx", "owncast", "root").block();
        repo.insertOffered("brandx", "akkoma", "root").block();
        repo.insertOffered("brandy", "phpbb", "root").block();

        List<ServiceCuration> xCatalog = repo.offeredForScope(scoped("brandx")).collectList().block();
        assertThat(xCatalog).extracting(ServiceCuration::serviceKey)
                .containsExactlyInAnyOrder("owncast", "akkoma");
        // DENY isolation: brand X NEVER sees brand Y's phpbb offer.
        assertThat(xCatalog).extracting(ServiceCuration::domain).containsOnly("brandx");

        List<ServiceCuration> yCatalog = repo.offeredForScope(scoped("brandy")).collectList().block();
        assertThat(yCatalog).extracting(ServiceCuration::serviceKey).containsExactly("phpbb");
        assertThat(yCatalog).extracting(ServiceCuration::domain).containsOnly("brandy");
    }

    @Test
    void superadminScope_seesEveryBrandsOfferedRows() {
        ServiceCurationRepository repo = repo();
        repo.insertOffered("brandx", "owncast", "root").block();
        repo.insertOffered("brandy", "phpbb", "root").block();

        List<ServiceCuration> all = repo.offeredForScope(superadminScope()).collectList().block();
        assertThat(all).extracting(ServiceCuration::domain)
                .containsExactlyInAnyOrder("brandx", "brandy");
    }

    @Test
    void withdraw_casOfferedToWithdrawn_removesFromAdminCatalog_butKeepsTheRow() {
        ServiceCurationRepository repo = repo();
        ServiceCuration offered = repo.insertOffered("brandx", "owncast", "root").block();

        Long rows = repo.markWithdrawn(offered.id()).block();
        assertThat(rows).isEqualTo(1L);

        // The admin no longer sees it (only 'offered' rows are returned).
        assertThat(repo.offeredForScope(scoped("brandx")).collectList().block()).isEmpty();
        // But the audit row survives for the superadmin per-domain view.
        List<ServiceCuration> domainView = repo.findByDomain("brandx").collectList().block();
        assertThat(domainView).hasSize(1);
        assertThat(domainView.get(0).state()).isEqualTo(ServiceCuration.STATE_WITHDRAWN);

        // A second withdraw is a no-op (CAS lost): rows == 0.
        assertThat(repo.markWithdrawn(offered.id()).block()).isEqualTo(0L);
    }

    @Test
    void findOffered_isExplicitDomainScoped() {
        ServiceCurationRepository repo = repo();
        repo.insertOffered("brandx", "owncast", "root").block();
        // The same service_key offered to brandx is NOT found under brandy.
        assertThat(repo.findOffered("brandy", "owncast").block()).isNull();
        assertThat(repo.findOffered("brandx", "owncast").block()).isNotNull();
    }

    @Test
    void nullScope_failsClosed_returnsNothing() {
        ServiceCurationRepository repo = repo();
        repo.insertOffered("brandx", "owncast", "root").block();
        // A null scope collapses to the NO_DOMAIN sentinel — matches no real brand.
        assertThat(repo.offeredForScope(null).collectList().block()).isEmpty();
    }
}
