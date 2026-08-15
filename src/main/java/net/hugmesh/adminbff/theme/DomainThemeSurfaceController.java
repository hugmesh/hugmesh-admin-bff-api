package net.hugmesh.adminbff.theme;

import io.swagger.v3.oas.annotations.Operation;
import jakarta.validation.constraints.Size;
import org.springframework.http.CacheControl;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
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

    /**
     * The domain's theme AS A STYLESHEET — what a surface actually links.
     *
     * <p>{@code <link rel="stylesheet" href="/bff/public/theme.css?domain=…">} in
     * {@code index.html}, which is a RENDER-BLOCKING fetch: the browser has the colours
     * before it paints, so there is no flash of the wrong brand. A JS-injected theme
     * cannot promise that, and the operator would see the default chrome flicker on
     * every navigation.
     *
     * <p>This endpoint only ever SERVES BYTES. It does not derive anything — the colour
     * maths has exactly one implementation, in the Studio's Python, and a second one here
     * would drift until the admin UI showed one theme and the page rendered another.
     * A domain with no render yet gets EMPTY CSS, which is exactly what the existing
     * entrypoint hook writes when {@code SNAP_THEME_CSS} is unset: every
     * {@code var(--sd-*, <literal>)} falls back and the shipped chrome renders
     * byte-identically. Un-themed, never half-themed.
     */
    @Operation(summary = "A domain's theme as CSS", operationId = "domainThemeCss")
    @GetMapping(value = "/bff/public/theme.css", produces = "text/css")
    public Mono<ResponseEntity<String>> css(
            @RequestParam(required = false)
            @Size(max = 255, message = "domain is too long")
            String domain) {
        return service.resolve(domain).map(t -> {
            String css = t.renderedCss() == null ? "" : t.renderedCss();
            return ResponseEntity.ok()
                    .contentType(MediaType.valueOf("text/css;charset=UTF-8"))
                    // Revalidate every time rather than cache. A theme change has to be
                    // visible on the next load -- an operator who reports "I changed it
                    // and nothing happened" is the failure this whole line keeps
                    // producing. The ETag keeps that cheap: unchanged themes answer 304
                    // with no body, so the cost of never caching is one conditional
                    // request, not one stylesheet.
                    .cacheControl(CacheControl.noCache())
                    .eTag(Integer.toHexString(css.hashCode()))
                    .body(css);
        });
    }
}
