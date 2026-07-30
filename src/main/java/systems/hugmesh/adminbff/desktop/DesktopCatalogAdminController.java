package systems.hugmesh.adminbff.desktop;

import io.swagger.v3.oas.annotations.Operation;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import systems.hugmesh.commons.security.DomainRegistry;
import systems.hugmesh.commons.security.PrincipalDomain;
import systems.hugmesh.adminbff.web.dto.DesktopCatalogEntryRequest;

import java.util.Map;

/**
 * The DESKTOP DISCOVER CATALOG curation surface (ADMIN/SUPERADMIN) at
 * {@code /bff/admin/desktop/catalog}. The admin curates which apps a brand's Plasma
 * Discover store MAY show; the store is DEFAULT-NONE so <b>add != enable</b> — a separate
 * enable/disable flip is what makes a ref appear.
 *
 * <h3>Authorization</h3>
 * Mounted under {@code /bff/admin/**} (coarse gate {@code hasAnyRole('ADMIN','SUPERADMIN')});
 * each method carries {@code @PreAuthorize("hasAnyRole('ADMIN','SUPERADMIN')")}. MOD/USER →
 * 403. The domain a row lands in / is read from is the CALLER'S brand via {@link PrincipalDomain}
 * (validated issuer, never a request field): a scoped ADMIN sees/mutates only their brand;
 * SUPERADMIN unscoped. The add stamps {@code scope.domain()} as the row's residency.
 */
@RestController
@RequestMapping("/bff/admin/desktop/catalog")
@Validated
public class DesktopCatalogAdminController {

    private static final Logger log = LoggerFactory.getLogger(DesktopCatalogAdminController.class);

    private final DesktopAppCatalogService service;
    private final DomainRegistry domainRegistry;

    public DesktopCatalogAdminController(DesktopAppCatalogService service, DomainRegistry domainRegistry) {
        this.service = service;
        this.domainRegistry = domainRegistry;
    }

    private PrincipalDomain scope(Authentication auth) {
        return PrincipalDomain.of(auth, domainRegistry);
    }

    private static String actor(Authentication auth) {
        return auth == null ? "superadmin" : auth.getName();
    }

    /** The catalog visible to the acting admin (own brand; SUPERADMIN all). */
    @PreAuthorize("hasAnyRole('ADMIN','SUPERADMIN')")
    @Operation(summary = "List", operationId = "desktopCatalogAdminList")
    @GetMapping("")
    public Flux<DesktopAppCatalogEntry> list(Authentication auth) {
        return service.list(scope(auth));
    }

    /** Add an app ref to the caller's brand catalog (DISABLED — add != enable). The domain
     *  is the caller's brand (NEVER the body). */
    @PreAuthorize("hasAnyRole('ADMIN','SUPERADMIN')")
    @Operation(summary = "Add", operationId = "desktopCatalogAdminAdd")
    @PostMapping("")
    @ResponseStatus(HttpStatus.CREATED)
    public Mono<DesktopAppCatalogEntry> add(@Valid @RequestBody DesktopCatalogEntryRequest b,
                                            Authentication auth) {
        PrincipalDomain scope = scope(auth);
        return service.add(scope.domain(), b.appRef(), b.displayName(), b.source(), actor(auth))
                .doOnNext(e -> log.info("[desktop-catalog] add ref={} domain={} by={}",
                        b.appRef(), scope.domain(), actor(auth)));
    }

    /** Enable a catalog row (make it appear in Discover). SCOPED. */
    @PreAuthorize("hasAnyRole('ADMIN','SUPERADMIN')")
    @Operation(summary = "Enable", operationId = "desktopCatalogAdminEnable")
    @PostMapping("/{id}/enable")
    public Mono<ResponseEntity<Map<String, Object>>> enable(
            @PathVariable @NotBlank @Size(max = 36) String id, Authentication auth) {
        return service.setEnabled(id, true, scope(auth))
                .map(n -> ResponseEntity.ok(Map.of("updated", n, "enabled", true)));
    }

    /** Disable a catalog row (remove it from Discover; keeps the row). SCOPED. */
    @PreAuthorize("hasAnyRole('ADMIN','SUPERADMIN')")
    @Operation(summary = "Disable", operationId = "desktopCatalogAdminDisable")
    @PostMapping("/{id}/disable")
    public Mono<ResponseEntity<Map<String, Object>>> disable(
            @PathVariable @NotBlank @Size(max = 36) String id, Authentication auth) {
        return service.setEnabled(id, false, scope(auth))
                .map(n -> ResponseEntity.ok(Map.of("updated", n, "enabled", false)));
    }

    /** Remove a catalog row entirely. SCOPED. */
    @PreAuthorize("hasAnyRole('ADMIN','SUPERADMIN')")
    @Operation(summary = "Remove", operationId = "desktopCatalogAdminRemove")
    @DeleteMapping("/{id}")
    public Mono<ResponseEntity<Map<String, Object>>> remove(
            @PathVariable @NotBlank @Size(max = 36) String id, Authentication auth) {
        return service.remove(id, scope(auth))
                .map(n -> ResponseEntity.ok(Map.of("removed", n)));
    }
}
