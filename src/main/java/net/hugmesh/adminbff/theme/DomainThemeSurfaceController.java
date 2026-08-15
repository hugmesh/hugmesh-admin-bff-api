package net.hugmesh.adminbff.theme;

import io.swagger.v3.oas.annotations.Operation;
import jakarta.validation.constraints.Size;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;

/**
 * The theme a surface should RENDER, resolved for one domain.
 *
 * <p>{@code GET /bff/public/theme?domain=…} — UNAUTHENTICATED, and it has to be: the
 * login page is the first thing an anonymous visitor sees and it has to be the right
 * colour before anyone has signed in. It exposes nothing beyond the domain's own public
 * appearance, which is visible to anyone who loads the page anyway.
 *
 * <p>WHY THE CALLER PASSES ITS DOMAIN RATHER THAN THE SERVER READING THE HOST HEADER:
 * there is no host-to-domain mapping on this platform. {@link
 * net.hugmesh.commons.security.DomainRegistry} maps a validated JWT ISSUER to a brand,
 * and nothing maps {@code login.example.test:8443} to one. Deriving the brand from the
 * {@code Host} header would therefore be a lookup that silently never matches, which
 * fails in the worst possible way for a theme — every domain quietly rendering the
 * default while the admin UI shows their choice saved. An omitted {@code domain} resolves
 * the mesh default, which is the correct answer for the single-brand mesh that is the
 * common deployment.
 */
@RestController
@Validated
public class DomainThemeSurfaceController {

    private final DomainThemeService service;

    public DomainThemeSurfaceController(DomainThemeService service) {
        this.service = service;
    }

    @Operation(summary = "Resolve a domain's theme", operationId = "domainThemeResolve")
    @GetMapping("/bff/public/theme")
    public Mono<PublicTheme> resolve(
            @RequestParam(required = false)
            @Size(max = 255, message = "domain is too long")
            String domain) {
        // Projected, never the stored record: see PublicTheme for why updatedBy must not
        // cross this boundary.
        return service.resolve(domain).map(PublicTheme::of);
    }
}
