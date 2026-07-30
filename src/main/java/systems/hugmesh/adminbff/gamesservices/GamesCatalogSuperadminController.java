package systems.hugmesh.adminbff.gamesservices;

import io.swagger.v3.oas.annotations.Operation;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import systems.hugmesh.adminbff.web.dto.GameCatalogEntryRequest;
import systems.hugmesh.adminbff.web.dto.GameCatalogEntryResponse;
import systems.hugmesh.adminbff.web.dto.GameDomainOfferRequest;
import systems.hugmesh.adminbff.web.dto.GameDomainOfferResponse;

/**
 * The GAMES APP-STORE SUPERADMIN console — runtime curation of the GLOBAL games-server
 * catalog + the per-domain offers (the games-services control plane, PR2).
 *
 * <h3>Authorization — SUPERADMIN-ONLY, CROSS-DOMAIN (defence-in-depth)</h3>
 * The coarse path gate ({@code SecurityConfig.commonRoutes}) on {@code /bff/superadmin/**}
 * is {@code hasRole('SUPERADMIN')}; EVERY endpoint here ALSO adds
 * {@code @PreAuthorize("hasRole('SUPERADMIN')")}. So:
 * <ul>
 *   <li>SUPERADMIN — ALLOWED. It curates the cross-domain catalog and offers servers to
 *       ANY domain, so these are deliberately NOT domain-scoped.</li>
 *   <li>ADMIN / MOD / USER — 403 (never clear the coarse {@code /bff/superadmin/**}
 *       gate, and walled again at the per-method gate).</li>
 * </ul>
 * There is NO delete: a catalog entry is soft-disabled ({@code enabled:false}); an offer is
 * withdrawn ({@code offeredBySuperadmin:false}). {@code created_by_subject} is stamped from
 * the SUPERADMIN's {@code jwt.getSubject()}.
 *
 * <p><b>Digest-pin.</b> A catalog create/update with a tag-only {@code imageRef} is a clean
 * 400 from the service's {@code ImageRef.validate} (arbitrary-container exec containment).
 */
@RestController
@RequestMapping("/bff/superadmin/games-services")
@Validated
public class GamesCatalogSuperadminController {

    private static final Logger log = LoggerFactory.getLogger(GamesCatalogSuperadminController.class);

    private final GamesCatalogService service;

    public GamesCatalogSuperadminController(GamesCatalogService service) {
        this.service = service;
    }

    private static String subject(Authentication auth) {
        if (auth != null && auth.getPrincipal() instanceof Jwt jwt) {
            return jwt.getSubject();
        }
        return auth == null ? null : auth.getName();
    }

    // ── GLOBAL CATALOG ───────────────────────────────────────────────────────────

    @PreAuthorize("hasRole('SUPERADMIN')")
    @Operation(summary = "List catalog", operationId = "gamesCatalogSuperadminListCatalog")
    @GetMapping("/catalog")
    public Flux<GameCatalogEntryResponse> listCatalog() {
        return service.listCatalog().map(GameCatalogEntryResponse::of);
    }

    @PreAuthorize("hasRole('SUPERADMIN')")
    @Operation(summary = "Get catalog", operationId = "gamesCatalogSuperadminGetCatalog")
    @GetMapping("/catalog/{slug}")
    public Mono<GameCatalogEntryResponse> getCatalog(
            @PathVariable @NotBlank @Size(max = 64) String slug) {
        return service.getCatalog(slug).map(GameCatalogEntryResponse::of);
    }

    @PreAuthorize("hasRole('SUPERADMIN')")
    @Operation(summary = "Create catalog", operationId = "gamesCatalogSuperadminCreateCatalog")
    @PostMapping("/catalog")
    @ResponseStatus(HttpStatus.CREATED)
    public Mono<GameCatalogEntryResponse> createCatalog(
            @Valid @RequestBody GameCatalogEntryRequest body, Authentication auth) {
        String subject = subject(auth);
        return service.createCatalog(body, subject)
                .doOnNext(e -> log.info("[games-catalog] create slug={} by={}", e.slug(), subject))
                .map(GameCatalogEntryResponse::of);
    }

    @PreAuthorize("hasRole('SUPERADMIN')")
    @Operation(summary = "Update catalog", operationId = "gamesCatalogSuperadminUpdateCatalog")
    @PutMapping("/catalog/{slug}")
    public Mono<GameCatalogEntryResponse> updateCatalog(
            @PathVariable @NotBlank @Size(max = 64) String slug,
            @Valid @RequestBody GameCatalogEntryRequest body) {
        return service.updateCatalog(slug, body).map(GameCatalogEntryResponse::of);
    }

    // ── PER-DOMAIN OFFERS ──────────────────────────────────────────────────────────

    @PreAuthorize("hasRole('SUPERADMIN')")
    @Operation(summary = "List offers", operationId = "gamesCatalogSuperadminListOffers")
    @GetMapping("/offers/{domain}")
    public Flux<GameDomainOfferResponse> listOffers(
            @PathVariable @NotBlank @Size(max = 253) String domain) {
        return service.listOffers(domain).map(GameDomainOfferResponse::of);
    }

    @PreAuthorize("hasRole('SUPERADMIN')")
    @Operation(summary = "Create offer", operationId = "gamesCatalogSuperadminCreateOffer")
    @PostMapping("/offers/{domain}")
    @ResponseStatus(HttpStatus.CREATED)
    public Mono<GameDomainOfferResponse> createOffer(
            @PathVariable @NotBlank @Size(max = 253) String domain,
            @Valid @RequestBody GameDomainOfferRequest body, Authentication auth) {
        String subject = subject(auth);
        return service.createOffer(domain, body, subject)
                .doOnNext(o -> log.info("[games-catalog] offer slug={} -> domain={} by={}",
                        o.slug(), domain, subject))
                .map(GameDomainOfferResponse::of);
    }

    @PreAuthorize("hasRole('SUPERADMIN')")
    @Operation(summary = "Update offer", operationId = "gamesCatalogSuperadminUpdateOffer")
    @PutMapping("/offers/{domain}/{slug}")
    public Mono<GameDomainOfferResponse> updateOffer(
            @PathVariable @NotBlank @Size(max = 253) String domain,
            @PathVariable @NotBlank @Size(max = 64) String slug,
            @Valid @RequestBody GameDomainOfferRequest body) {
        return service.updateOffer(domain, slug, body).map(GameDomainOfferResponse::of);
    }
}
