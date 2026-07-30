package systems.hugmesh.adminbff.servicecatalog;

import io.swagger.v3.oas.annotations.Operation;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Flux;
import systems.hugmesh.commons.security.DomainRegistry;
import systems.hugmesh.commons.security.PrincipalDomain;

/**
 * The brand-ADMIN read of the App-Store offered catalog — the BOTTOM tier of the two-tier
 * curation. {@code GET /bff/admin/service-store} returns ONLY the services the SUPERADMIN
 * has OFFERED to the CALLER'S OWN domain (the {@code service_curation} offered rows).
 *
 * <h3>The two-tier proof + DOMAIN ISOLATION</h3>
 * The domain is resolved from the CRYPTOGRAPHICALLY-VALIDATED JWT issuer via
 * {@link PrincipalDomain}{@code .of(auth, registry)} (which uses {@code Roles.domainOf}) — NEVER
 * from the request. A brand-X admin sees ONLY brand-X's offered catalog and can NEVER read
 * brand-Y's catalog; a SUPERADMIN (unscoped) sees every brand's offered rows. Fail-closed on
 * an unknown issuer (the foundation's behaviour): the scope collapses to the NO_DOMAIN
 * sentinel, which matches no real brand's rows.
 *
 * <h3>Authorization</h3>
 * Mounted under {@code /bff/admin/**} (coarse gate {@code hasAnyRole('ADMIN','SUPERADMIN')}
 * in {@link systems.hugmesh.adminbff.config.SecurityConfig}); the method carries
 * {@code @PreAuthorize("hasAnyRole('ADMIN','SUPERADMIN')")}. MOD / USER → 403 (never clear
 * the coarse gate). This is a READ-ONLY surface — an admin cannot offer/withdraw (that is
 * the SUPERADMIN-only {@code /bff/superadmin/service-store} top tier).
 */
@RestController
@RequestMapping("/bff/admin/service-store")
public class AdminServiceStoreController {

    private final ServiceCurationService service;
    /** Issuer-to-domain registry — resolves the acting admin's tenant scope from the
     *  cryptographically-validated JWT issuer. */
    private final DomainRegistry domainRegistry;

    public AdminServiceStoreController(ServiceCurationService service, DomainRegistry domainRegistry) {
        this.service = service;
        this.domainRegistry = domainRegistry;
    }

    /**
     * The offered catalog VISIBLE to the acting admin's own brand. The scope is resolved
     * ONCE from the validated JWT issuer (NOT a request field), so a brand-X admin sees only
     * brand-X's offered services. SUPERADMIN is unscoped (sees all brands' offered rows).
     */
    @PreAuthorize("hasAnyRole('ADMIN','SUPERADMIN')")
    @Operation(summary = "My domain catalog", operationId = "adminServiceStoreMyDomainCatalog")
    @GetMapping
    public Flux<ServiceCuration> myDomainCatalog(Authentication auth) {
        PrincipalDomain scope = PrincipalDomain.of(auth, domainRegistry);
        return service.offeredCatalog(scope);
    }
}
