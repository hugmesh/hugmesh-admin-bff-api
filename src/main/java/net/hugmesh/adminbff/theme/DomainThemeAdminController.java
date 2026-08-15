package net.hugmesh.adminbff.theme;

import io.swagger.v3.oas.annotations.Operation;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import net.hugmesh.adminbff.web.dto.DomainThemeRequest;
import net.hugmesh.commons.security.DomainRegistry;
import net.hugmesh.commons.security.PrincipalDomain;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;
import reactor.core.publisher.Mono;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Per-domain theme administration (operator ask: "let themes be set different for
 * different domains by the studio and by the superadmin or admin of a domain in the web
 * ui").
 *
 * <ul>
 *   <li>{@code GET    /bff/admin/themes}           — every theme the caller may see.</li>
 *   <li>{@code GET    /bff/admin/themes/{domain}}  — one domain's effective theme, and
 *       whether it is INHERITED or its own.</li>
 *   <li>{@code PUT    /bff/admin/themes/{domain}}  — set it.</li>
 *   <li>{@code DELETE /bff/admin/themes/{domain}}  — clear it, back to inheriting.</li>
 * </ul>
 *
 * <p>{@code {domain}} accepts the reserved literal {@link #DEFAULT_SEGMENT} for the MESH
 * DEFAULT, which has no name of its own (its key is the empty string, which cannot be a
 * path segment). The underscore is what makes the literal safe: a registry-sanitized
 * domain is {@code [a-z0-9-]}, so {@code _default} can never collide with a real one.
 *
 * <p>AUTHORIZATION IS NOT HERE. {@code @PreAuthorize("hasRole('ADMIN')")} only establishes
 * that the caller is SOME domain's admin; which domain they may touch is
 * {@link DomainThemeService#canManage}, and this controller deliberately does not
 * re-implement that decision — it passes the scope down and lets the service refuse. The
 * two sources of role truth on this platform have already disagreed once in production
 * (the shell's menu offered Moderation while the gateway refused it), so a check that
 * lives in two places is a check that will eventually differ in two places.
 */
@RestController
@RequestMapping("/bff/admin/themes")
@Validated
public class DomainThemeAdminController {

    /** Reserved path segment for the mesh default. Not a legal domain name. */
    public static final String DEFAULT_SEGMENT = "_default";

    private final DomainThemeService service;
    private final DomainRegistry domainRegistry;

    public DomainThemeAdminController(DomainThemeService service, DomainRegistry domainRegistry) {
        this.service = service;
        this.domainRegistry = domainRegistry;
    }

    private PrincipalDomain scope(Authentication auth) {
        return PrincipalDomain.of(auth, domainRegistry);
    }

    /** The reserved segment resolved to the storage key the service and repo expect. */
    private static String target(String segment) {
        return DEFAULT_SEGMENT.equals(segment)
                ? DomainTheme.MESH_DEFAULT
                : DomainTheme.normalizeDomain(segment);
    }

    @PreAuthorize("hasRole('ADMIN')")
    @Operation(summary = "List themes", operationId = "domainThemeAdminList")
    @GetMapping
    public Mono<Map<String, Object>> list(Authentication auth) {
        return service.list(scope(auth)).collectList().map(l -> Map.of("themes", l));
    }

    /**
     * One domain's EFFECTIVE theme plus whether it owns that theme or inherits it.
     *
     * <p>The flag is the point. {@code resolve()} alone cannot distinguish "this domain
     * chose the mesh default" from "this domain has no row at all" — the repository keeps
     * those separable precisely so an editor can show the difference, and an editor that
     * cannot tell them apart would offer Clear on a domain with nothing to clear.
     */
    @PreAuthorize("hasRole('ADMIN')")
    @Operation(summary = "Get a domain's theme", operationId = "domainThemeAdminGet")
    @GetMapping("/{domain}")
    public Mono<Map<String, Object>> get(
            @PathVariable
            @NotBlank(message = "domain is required")
            @Size(max = 255, message = "domain is too long")
            String domain,
            Authentication auth) {
        String t = target(domain);
        return guard(t, scope(auth)).then(Mono.defer(() ->
                service.effective(t).map(e -> {
                    Map<String, Object> body = new LinkedHashMap<>();
                    body.put("theme", e.theme());
                    body.put("inherited", e.inherited());
                    return body;
                })));
    }

    @PreAuthorize("hasRole('ADMIN')")
    @Operation(summary = "Set a domain's theme", operationId = "domainThemeAdminSet")
    @PutMapping("/{domain}")
    public Mono<DomainTheme> set(
            @PathVariable
            @NotBlank(message = "domain is required")
            @Size(max = 255, message = "domain is too long")
            String domain,
            @Valid @RequestBody DomainThemeRequest body,
            Authentication auth) {
        String t = target(domain);
        return rejectUnknownDomain(t).then(Mono.defer(() -> service.set(
                new DomainTheme(t, body.preset(), body.ramp(), body.style(), body.decor(),
                        body.primaryHex(), body.secondaryHex(), actor(auth),
                        body.renderedCss(), body.renderedCss() == null ? null : actor(auth)),
                scope(auth), actor(auth))));
    }

    @PreAuthorize("hasRole('ADMIN')")
    @Operation(summary = "Clear a domain's theme", operationId = "domainThemeAdminClear")
    @DeleteMapping("/{domain}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public Mono<Void> clear(
            @PathVariable
            @NotBlank(message = "domain is required")
            @Size(max = 255, message = "domain is too long")
            String domain,
            Authentication auth) {
        return service.clear(target(domain), scope(auth));
    }

    /** 403 unless the caller may manage this domain — the same decision {@code set} and
     *  {@code clear} make inside the service, applied to the read of a single domain. */
    private Mono<Void> guard(String target, PrincipalDomain scope) {
        return service.canManage(scope, target)
                ? Mono.empty()
                : Mono.error(new ResponseStatusException(HttpStatus.FORBIDDEN,
                        "not permitted to read the theme for domain '" + target + "'"));
    }

    /**
     * In a genuine multi-brand mesh, refuse a theme for a domain that does not exist —
     * otherwise a superadmin's typo becomes a row nothing ever reads and no UI lists.
     *
     * <p>Only in multi-issuer mode, and never for the mesh default. In a single-issuer
     * mesh every principal's domain is the back-compat sentinel {@code "default"}, which
     * {@link DomainRegistry#isKnownDomain} returns FALSE for by design — so applying this
     * guard unconditionally would reject every legitimate write on the common
     * single-brand deployment.
     */
    private Mono<Void> rejectUnknownDomain(String target) {
        if (target.equals(DomainTheme.MESH_DEFAULT) || !domainRegistry.isMultiIssuer()) {
            return Mono.empty();
        }
        return domainRegistry.isKnownDomain(target)
                ? Mono.empty()
                : Mono.error(new ResponseStatusException(HttpStatus.BAD_REQUEST,
                        "unknown domain '" + target + "'"));
    }

    /** The acting admin's identity, recorded as {@code updated_by} — a theme is a
     *  visible, mesh-wide change and "who made everything pink?" needs an answer. */
    private static String actor(Authentication auth) {
        return auth == null ? "admin" : auth.getName();
    }
}
