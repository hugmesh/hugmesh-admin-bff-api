package systems.hugmesh.adminbff.servicecatalog;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.data.r2dbc.test.autoconfigure.DataR2dbcTest;
import org.springframework.context.annotation.Import;
import org.springframework.r2dbc.core.DatabaseClient;
import org.springframework.test.context.ActiveProfiles;
import reactor.test.StepVerifier;
import systems.hugmesh.commons.security.DomainRegistry;
import systems.hugmesh.commons.security.PrincipalDomain;
import systems.hugmesh.adminbff.support.TestDatabaseConfig;
import systems.hugmesh.commons.web.ApiException;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Service-layer TWO-TIER + tenant-isolation for {@link ServiceCurationService} over a REAL
 * H2 repo. Proves the whole offer/withdraw/admin-read surface is domain-correct:
 * <ul>
 *   <li>the superadmin OFFERS to an explicit domain (idempotent re-offer = no-op);</li>
 *   <li>a brand ADMIN's {@code offeredCatalog} sees ONLY their own domain's offered rows —
 *       brand X never sees brand Y (the two-tier proof, two domains, DENY isolation);</li>
 *   <li>a withdraw of a non-offered (domain, service) is a clean 404;</li>
 *   <li>SUPERADMIN's offeredCatalog is unscoped (both brands).</li>
 * </ul>
 */
@DataR2dbcTest
@Import(TestDatabaseConfig.class)
@ActiveProfiles("test")
class ServiceCurationServiceDomainScopeTest {

    @Autowired DatabaseClient db;

    private static final DomainRegistry REGISTRY = new DomainRegistry("",
            "https://idp.brandx.example=brandx,https://idp.brandy.example=brandy");

    @org.junit.jupiter.api.BeforeEach
    void clear() {
        // The @DataR2dbcTest H2 store is per-CLASS; clear between methods.
        db.sql("DELETE FROM service_curation").fetch().rowsUpdated().block();
    }

    private ServiceCurationService svc() {
        return new ServiceCurationService(new ServiceCurationRepository(systems.hugmesh.adminbff.testutil.R2dbcRepos.of(db, systems.hugmesh.adminbff.servicecatalog.ServiceCurationR2dbcRepository.class)));
    }

    private static PrincipalDomain adminX() { return ScopeFixtures.admin("brandx", REGISTRY); }
    private static PrincipalDomain adminY() { return ScopeFixtures.admin("brandy", REGISTRY); }
    private static PrincipalDomain superadmin() { return ScopeFixtures.superadmin(REGISTRY); }

    @Test
    void offerIsIdempotent_andAdminSeesOnlyTheirDomain() {
        ServiceCurationService svc = svc();
        svc.offer("brandx", "owncast", "root").block();
        // Idempotent re-offer returns the same row (no second offered row).
        svc.offer("brandx", "owncast", "root").block();
        assertThat(svc.listForDomain("brandx").collectList().block()).hasSize(1);

        svc.offer("brandy", "phpbb", "root").block();

        // The brand-X admin sees ONLY owncast; the brand-Y admin sees ONLY phpbb.
        List<ServiceCuration> x = svc.offeredCatalog(adminX()).collectList().block();
        assertThat(x).extracting(ServiceCuration::serviceKey).containsExactly("owncast");
        assertThat(x).extracting(ServiceCuration::domain).containsOnly("brandx");

        List<ServiceCuration> y = svc.offeredCatalog(adminY()).collectList().block();
        assertThat(y).extracting(ServiceCuration::serviceKey).containsExactly("phpbb");

        // SUPERADMIN sees both brands' offered rows.
        assertThat(svc.offeredCatalog(superadmin()).collectList().block())
                .extracting(ServiceCuration::domain).containsExactlyInAnyOrder("brandx", "brandy");
    }

    @Test
    void withdraw_removesFromAdminCatalog() {
        ServiceCurationService svc = svc();
        svc.offer("brandx", "owncast", "root").block();
        svc.withdraw("brandx", "owncast", "root").block();
        assertThat(svc.offeredCatalog(adminX()).collectList().block()).isEmpty();
    }

    @Test
    void withdraw_nonOffered_is404() {
        StepVerifier.create(svc().withdraw("brandx", "ghost", "root"))
                .expectErrorSatisfies(e -> assertThat(((ApiException) e).status().value()).isEqualTo(404))
                .verify();
    }

    @Test
    void offeredCatalog_failClosedForUnknownIssuerScope() {
        ServiceCurationService svc = svc();
        svc.offer("brandx", "owncast", "root").block();
        // A scope whose issuer is not in the registry resolves to NO_DOMAIN (fail-closed),
        // which matches no real brand's rows.
        PrincipalDomain unknown = PrincipalDomain.of(
                new org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken(
                        org.springframework.security.oauth2.jwt.Jwt.withTokenValue("t")
                                .header("alg", "none")
                                .issuedAt(java.time.Instant.now())
                                .expiresAt(java.time.Instant.now().plusSeconds(60))
                                .subject("u").issuer("https://idp.unknown.example")
                                .claim("roles", java.util.List.of("admin")).build(),
                        java.util.List.of(new org.springframework.security.core.authority.SimpleGrantedAuthority("ROLE_ADMIN"))),
                REGISTRY);
        assertThat(svc.offeredCatalog(unknown).collectList().block()).isEmpty();
    }
}
