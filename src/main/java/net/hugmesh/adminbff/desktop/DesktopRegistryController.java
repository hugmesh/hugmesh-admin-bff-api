package net.hugmesh.adminbff.desktop;

import io.swagger.v3.oas.annotations.Operation;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import net.hugmesh.commons.security.DomainRegistry;
import net.hugmesh.commons.security.PrincipalDomain;
import net.hugmesh.commons.web.ApiException;

/**
 * The DESKTOP DISCOVER REGISTRY surface — the BFF-forwarded, DOMAIN-LOCKED Flatpak/OCI index
 * the desktop image points Plasma Discover at. SECURITY-CRITICAL: this is the only path a
 * non-admin desktop user reaches, and it must serve ONLY their own brand's ENABLED apps.
 *
 * <h3>Authorization (fail-closed, defence-in-depth)</h3>
 * <ul>
 *   <li>Coarse gate ({@code SecurityConfig.commonRoutes}) on {@code /bff/desktop/registry/**}
 *       = {@code hasRole('DISCOVER')} — only an SSO user holding the brand's {@code discover}
 *       role reaches it; a non-discover principal is 403.</li>
 *   <li>DOMAIN-LOCK: the domain is resolved from the CRYPTOGRAPHICALLY-VALIDATED JWT issuer
 *       via {@link PrincipalDomain} (NEVER a request field). The registry serves ONLY that
 *       domain's enabled refs. A token with no resolvable tenant collapses to the
 *       {@link PrincipalDomain#NO_DOMAIN} sentinel → matches no real brand → serves nothing
 *       (fail-closed). A SUPERADMIN hitting this user-surface is treated as scoped to its
 *       home domain (this is a per-user store, not the cross-domain console).</li>
 *   <li>ENABLED-ONLY: a ref that is not in this domain's enabled allowlist (disabled,
 *       absent, or another brand's) → 404 (deny, no cross-domain leak).</li>
 * </ul>
 * The upstream fetch ships DARK behind {@code app.desktop.registry.enabled=false} + the
 * {@link NoopDesktopRegistryClient}; the FILTERING + authz here are REAL + tested.
 */
@RestController
@RequestMapping("/bff/desktop/registry")
@Validated
public class DesktopRegistryController {

    private final DesktopRegistryService registry;
    private final DomainRegistry domainRegistry;

    public DesktopRegistryController(DesktopRegistryService registry, DomainRegistry domainRegistry) {
        this.registry = registry;
        this.domainRegistry = domainRegistry;
    }

    /** The caller's brand from the validated issuer; fail-closed (NO_DOMAIN sentinel) on an
     *  unresolvable tenant. For this user-surface even a SUPERADMIN is scoped to its home
     *  brand (the cross-domain console is the admin surface, not the desktop store). */
    private String lockedDomain(Authentication auth) {
        PrincipalDomain scope = PrincipalDomain.of(auth, domainRegistry);
        return scope.domain();
    }

    /** The Discover index — ONLY this domain's ENABLED refs. Empty for a brand with no
     *  enabled apps (default-NONE) or an unresolvable tenant (fail-closed). */
    @PreAuthorize("hasRole('DISCOVER')")
    @Operation(summary = "Index", operationId = "desktopRegistryIndex")
    @GetMapping("")
    public Flux<DesktopAppCatalogEntry> index(Authentication auth) {
        return registry.listEnabled(lockedDomain(auth));
    }

    /**
     * Proxy ONE ref's upstream index — ONLY if it is in THIS domain's enabled allowlist; a
     * not-in-allowlist ref (disabled / absent / cross-domain) is a 404 (deny, no leak). The
     * upstream fetch ships dark by default.
     */
    @PreAuthorize("hasRole('DISCOVER')")
    @Operation(summary = "Ref", operationId = "desktopRegistryRef")
    @GetMapping("/refs/{appRef}")
    public Mono<String> ref(@PathVariable @NotBlank @Size(max = 512) String appRef, Authentication auth) {
        return registry.fetchRef(lockedDomain(auth), appRef)
                .switchIfEmpty(Mono.error(ApiException.notFound(
                        "ref not available in this domain's enabled Discover allowlist")));
    }
}
