package net.hugmesh.adminbff.optionalservices;

import io.swagger.v3.oas.annotations.Operation;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;
import net.hugmesh.adminbff.web.dto.SetOptionalServiceEnabledRequest;
import net.hugmesh.commons.web.ApiException;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * The SUPERADMIN OPTIONAL-SERVICES control surface at
 * {@code /bff/superadmin/optional-services} — the missing half of "an image ships with only its
 * selected services UNTIL A SUPERADMIN ENABLES OTHERS". The image half is the generator's baked
 * {@code apps/} tree; THIS is the runtime half: a superadmin writes {@code spec.enabled} on an
 * {@code OptionalService} CR and the Lease-gated
 * {@link OptionalServiceReconciler} converges it onto the {@code apps/13a} ApplicationSet
 * element + the {@code installed-services} greying boolean.
 *
 * <p>The gateway route and the {@code ROLE_SUPERADMIN} {@code route_access} floor for this path
 * were already in place before this controller existed (the path 404'd from admin-bff), so no
 * new gateway row is needed.
 *
 * <h3>Authorization — SUPERADMIN-ONLY, CROSS-DOMAIN (defence-in-depth)</h3>
 * The coarse path gate in {@code SecurityConfig.commonRoutes} on {@code /bff/superadmin/**} is
 * {@code hasRole('SUPERADMIN')}; BOTH endpoints here ALSO carry
 * {@code @PreAuthorize("hasRole('SUPERADMIN')")}, exactly as
 * {@link net.hugmesh.adminbff.gamesservices.GamesCatalogSuperadminController} and
 * {@link net.hugmesh.adminbff.backingservices.BackingServiceController} do. Installing or
 * removing a cluster service is infra-wide, not per-brand, so these are deliberately NOT
 * domain-scoped: ADMIN / MOD / USER never clear the coarse gate and are walled again per method.
 *
 * <p>NOT step-up-gated. The two step-up-gated superadmin planes in this repo reuse a plane's OWN
 * gate ({@code PhoneLockStepUpGate}, {@code BackingServiceStepUpGate}); there is no
 * optional-services gate and inventing one would be a new style. The games-catalog superadmin
 * plane is the precedent followed here: role floor only.
 *
 * <h3>Endpoints</h3>
 * <ul>
 *   <li>{@code GET ""} — the CATALOGUE: every slug the platform knows, its current CR state, and
 *       whether it is actually TOGGLEABLE. A slug the registry cannot reconcile is reported
 *       {@code toggleable:false} with a NAMED reason, never listed as if it worked — that is
 *       precisely the {@code character-forge} defect this surface exists to make impossible.
 *       Live even while the reconciler is dark, with {@code reconcilerEnabled:false} saying so.</li>
 *   <li>{@code PUT "/{slug}"} — set {@code enabled} with an audit {@code reason}. Unknown slug
 *       -> 404; known-but-unactionable slug -> 422 with the named reason and NO write; dark
 *       reconciler -> 503 {@code dark:true} and NO write; API-server rejection -> 422; happy ->
 *       the written desired state plus any partial-actuation warnings.</li>
 * </ul>
 */
@RestController
@RequestMapping("/bff/superadmin/optional-services")
@Validated
public class OptionalServiceSuperadminController {

    /** The CRD's slug enum values are short; this is a cheap pre-validation wall, not the gate. */
    private static final int MAX_SLUG = 64;

    private final OptionalServiceAdminService service;

    public OptionalServiceSuperadminController(OptionalServiceAdminService service) {
        this.service = service;
    }

    private static String subject(Authentication auth) {
        if (auth != null && auth.getPrincipal() instanceof Jwt jwt) {
            return jwt.getSubject();
        }
        return auth == null ? null : auth.getName();
    }

    // ── catalogue (read; live even while the reconciler is dark) ────────────────────

    @PreAuthorize("hasRole('SUPERADMIN')")
    @Operation(summary = "Optional-services catalogue + toggleability",
            operationId = "optionalServicesCatalogue")
    @GetMapping
    public Mono<Map<String, Object>> catalogue() {
        return service.catalogue();
    }

    // ── toggle (mutating; refuses rather than no-ops) ───────────────────────────────

    @PreAuthorize("hasRole('SUPERADMIN')")
    @Operation(summary = "Enable or disable an optional service",
            operationId = "optionalServicesSetEnabled")
    @PutMapping("/{slug}")
    public Mono<ResponseEntity<Map<String, Object>>> setEnabled(
            @PathVariable @NotBlank @Size(max = MAX_SLUG) String slug,
            @Valid @RequestBody SetOptionalServiceEnabledRequest body,
            Authentication auth) {
        String actor = subject(auth);
        if (actor == null || actor.isBlank()) {
            return Mono.error(ApiException.unauthorized("no subject on token"));
        }
        return service.setEnabled(slug, Boolean.TRUE.equals(body.enabled()), body.reason(), actor)
                .map(ResponseEntity::ok)
                .onErrorResume(OptionalServiceAdminService.UnknownSlugException.class,
                        e -> Mono.error(ApiException.notFound(e.getMessage())))
                .onErrorResume(OptionalServiceAdminService.NotToggleableException.class,
                        e -> Mono.error(ApiException.unprocessable(e.getMessage())))
                .onErrorResume(OptionalServiceWriteException.class, e ->
                        e.kind() == OptionalServiceWriteException.Kind.REJECTED
                                ? Mono.error(ApiException.unprocessable(e.getMessage()))
                                : e.kind() == OptionalServiceWriteException.Kind.NOT_WIRED
                                        ? Mono.just(darkResponse(e.getMessage()))
                                        : Mono.error(ApiException.serviceUnavailable(e.getMessage())));
    }

    /** The 503 descriptor the mutating verb returns while the reconciler is dark — nothing was written. */
    private static ResponseEntity<Map<String, Object>> darkResponse(String message) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("dark", true);
        body.put("error", message);
        body.put("note", "the optional-services control plane ships dark "
                + "(app.optional-services.reconcile.enabled=false) — authorization is live and the "
                + "catalogue reads honestly, but NO OptionalService CR was written");
        return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE).body(body);
    }
}
