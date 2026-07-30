package systems.hugmesh.adminbff.announcement;

import io.swagger.v3.oas.annotations.Operation;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;
import systems.hugmesh.commons.security.DomainRegistry;
import systems.hugmesh.commons.security.PrincipalDomain;
import systems.hugmesh.adminbff.web.dto.AnnouncementRequest;

import java.util.Map;

/**
 * ADMIN-only announcements CRUD + scheduling (reactive WebFlux). Admin gating is
 * DEFENCE IN DEPTH identical to {@link systems.hugmesh.adminbff.AdminController}:
 * the gateway denies {@code /bff/admin/**} to non-admins, the resource-server filter
 * re-applies {@code hasRole('ADMIN')} on the path, AND
 * {@code @PreAuthorize("hasRole('ADMIN')")} re-checks at every method here.
 *
 * <ul>
 *   <li>{@code POST   /bff/admin/announcements}        — create → the new row (201).</li>
 *   <li>{@code GET    /bff/admin/announcements}        — full list (newest first).</li>
 *   <li>{@code GET    /bff/admin/announcements/{id}}   — one announcement.</li>
 *   <li>{@code PUT    /bff/admin/announcements/{id}}   — update (incl. publish/archive).</li>
 *   <li>{@code DELETE /bff/admin/announcements/{id}}   — delete (204).</li>
 * </ul>
 *
 * <p>Validation: jakarta Bean Validation on the typed {@link AnnouncementRequest}
 * (@Valid) — a malformed body is a clean 400 {@code {error,fields}} via the existing
 * reactive {@code ValidationExceptionHandler}. The cross-field rules (at-least-one
 * target, window order) live in {@link AnnouncementService} and surface as a 400 via
 * {@code ApiExceptionHandler}. {@code body_html} is sanitised server-side before
 * storage; publishing a {@code target_akkoma} announcement propagates a LOCAL-ONLY
 * akkoma post (best-effort stub-seam), removed on unpublish/archive/delete.
 *
 * <p>DOMAIN SCOPING (multi-tenancy P1 fix — changeset 061): every admin mutation is
 * scoped to the acting principal's brand via {@link PrincipalDomain}. The scope is
 * resolved ONCE per request from the validated JWT issuer via {@link DomainRegistry}
 * (the same mechanism as {@link systems.hugmesh.adminbff.AdminController}) and
 * threaded to the service. A brand-X admin cannot see or mutate brand-Y announcements;
 * SUPERADMIN is unscoped (sees/mutates all brands).
 */
@RestController
@RequestMapping("/bff/admin/announcements")
@Validated
public class AnnouncementAdminController {

    private final AnnouncementService service;
    /** Issuer-to-domain registry — resolves the acting principal's tenant scope from
     *  the cryptographically-validated JWT issuer. */
    private final DomainRegistry domainRegistry;

    public AnnouncementAdminController(AnnouncementService service, DomainRegistry domainRegistry) {
        this.service = service;
        this.domainRegistry = domainRegistry;
    }

    /**
     * The tenant SCOPE the acting principal operates under, resolved from their
     * validated Casdoor JWT issuer. A brand-scoped ADMIN is constrained to their own
     * brand's rows; SUPERADMIN is unscoped (sees + mutates all brands).
     */
    private PrincipalDomain scope(Authentication auth) {
        return PrincipalDomain.of(auth, domainRegistry);
    }

    @PreAuthorize("hasRole('ADMIN')")
    @Operation(summary = "Create", operationId = "announcementAdminCreate")
    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    public Mono<Announcement> create(@Valid @RequestBody AnnouncementRequest body, Authentication auth) {
        return service.create(body, actor(auth), scope(auth));
    }

    @PreAuthorize("hasRole('ADMIN')")
    @Operation(summary = "List", operationId = "announcementAdminList")
    @GetMapping
    public Mono<Map<String, Object>> list(Authentication auth) {
        return service.list(scope(auth)).collectList().map(list -> Map.of("announcements", list));
    }

    @PreAuthorize("hasRole('ADMIN')")
    @Operation(summary = "Get", operationId = "announcementAdminGet")
    @GetMapping("/{id}")
    public Mono<Announcement> get(
            @PathVariable
            @NotBlank(message = "id is required")
            @Size(max = 100, message = "id is too long")
            String id,
            Authentication auth) {
        return service.get(id, scope(auth));
    }

    @PreAuthorize("hasRole('ADMIN')")
    @Operation(summary = "Update", operationId = "announcementAdminUpdate")
    @PutMapping("/{id}")
    public Mono<Announcement> update(
            @PathVariable
            @NotBlank(message = "id is required")
            @Size(max = 100, message = "id is too long")
            String id,
            @Valid @RequestBody AnnouncementRequest body,
            Authentication auth) {
        return service.update(id, body, actor(auth), scope(auth));
    }

    @PreAuthorize("hasRole('ADMIN')")
    @Operation(summary = "Delete", operationId = "announcementAdminDelete")
    @DeleteMapping("/{id}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public Mono<Void> delete(
            @PathVariable
            @NotBlank(message = "id is required")
            @Size(max = 100, message = "id is too long")
            String id,
            Authentication auth) {
        return service.delete(id, scope(auth));
    }

    /** The acting admin's identity (JWT subject/name) for {@code created_by}. */
    private static String actor(Authentication auth) {
        return auth == null ? "admin" : auth.getName();
    }
}
