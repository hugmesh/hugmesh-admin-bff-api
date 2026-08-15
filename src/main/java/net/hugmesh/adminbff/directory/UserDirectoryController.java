package net.hugmesh.adminbff.directory;

import io.swagger.v3.oas.annotations.Operation;

import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.Size;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;
import net.hugmesh.commons.security.DomainRegistry;
import net.hugmesh.commons.security.PrincipalDomain;

import java.util.List;

/**
 * The USER TYPEAHEAD read surface — {@code GET /bff/admin/users/search?q=&limit=}.
 *
 * <p>Backs the type-to-filter user pickers in the admin console (delegation
 * suspend/domain-lock/namespace-grant, the external-client grant). Every one of those was
 * previously a bare free-text box in which an admin had to already know a user's exact
 * Casdoor username.
 *
 * <h3>The scope is the point</h3>
 * The result set is scoped to the CALLER'S OWN BRAND, derived from the
 * cryptographically-validated JWT issuer via {@link PrincipalDomain} — the same resolution
 * {@code AdminController} applies to the allowlist read it shares a data source with.
 *
 * <p>There is deliberately NO {@code domain} request parameter. Accepting one would make
 * brand isolation a function of what the browser asked for; here a brand-X ADMIN cannot
 * name brand Y at all, and the underlying finder never reads brand Y's rows. SUPERADMIN —
 * the cross-brand infra role that already sees every brand's allowlist — is unscoped.
 *
 * <p>Filtering and the row cap are BOTH applied server-side (see
 * {@link UserDirectoryService}). Returning the full directory for the browser to filter
 * would be the enumeration hole this endpoint exists to close.
 *
 * <h3>Authorization</h3>
 * Coarse-gated by {@code /bff/admin/**} = {@code hasAnyRole('ADMIN','SUPERADMIN')} in
 * {@code SecurityConfig}, with the per-method {@code @PreAuthorize} below as
 * defence-in-depth: MOD/USER 403, anonymous 401.
 */
@RestController
@RequestMapping("/bff/admin/users")
@Validated
public class UserDirectoryController {

    /** Default page size when the caller does not ask for one — a typeahead list length. */
    static final int DEFAULT_LIMIT = 10;

    private final UserDirectoryService service;
    private final DomainRegistry domainRegistry;

    public UserDirectoryController(UserDirectoryService service, DomainRegistry domainRegistry) {
        this.service = service;
        this.domainRegistry = domainRegistry;
    }

    /**
     * Search the caller's own brand's user directory.
     *
     * @param q     the typed fragment, matched case-insensitively against both the Casdoor
     *              username and the invite handle. Blank returns an empty list (the
     *              picker's "keep typing" state) rather than the whole directory.
     * @param limit requested row cap; clamped server-side to
     *              {@link UserDirectoryService#MAX_LIMIT} regardless of what is asked for.
     */
    @PreAuthorize("hasAnyRole('ADMIN','SUPERADMIN')")
    @Operation(summary = "Search users", operationId = "adminUserSearch")
    @GetMapping("/search")
    public Mono<List<DirectoryUser>> search(
            @RequestParam(name = "q", required = false, defaultValue = "")
            @Size(max = 200, message = "q is too long") String q,
            @RequestParam(name = "limit", required = false, defaultValue = "" + DEFAULT_LIMIT)
            @Min(value = 1, message = "limit must be at least 1")
            @Max(value = UserDirectoryService.MAX_LIMIT, message = "limit is too large") int limit,
            Authentication auth) {
        return service.search(PrincipalDomain.of(auth, domainRegistry), q, limit);
    }
}
