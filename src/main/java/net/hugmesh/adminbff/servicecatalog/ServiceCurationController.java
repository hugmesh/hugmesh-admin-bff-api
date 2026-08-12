package net.hugmesh.adminbff.servicecatalog;

import io.swagger.v3.oas.annotations.Operation;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import net.hugmesh.adminbff.web.dto.ServiceCurationRequest;

/**
 * The SUPERADMIN App-Store CURATION console — superadmin CRUD over the per-domain offered
 * catalog ({@code service_curation}, schema 100). The TOP tier of the two-tier curation:
 * the cross-domain infra superadmin OFFERS / WITHDRAWS a {@code service_key} FOR a specific
 * {@code domain}; a brand admin only READS their own domain's offered set (the bottom tier,
 * {@code AdminServiceStoreController}).
 *
 * <h3>Authorization — SUPERADMIN-ONLY (defence-in-depth)</h3>
 * Mounted under {@code /bff/superadmin/**}, whose coarse gate in
 * {@link net.hugmesh.adminbff.config.SecurityConfig} is {@code hasRole('SUPERADMIN')}
 * (admin/mod/user never clear it). EVERY method ALSO carries
 * {@code @PreAuthorize("hasRole('SUPERADMIN')")} — so:
 * <ul>
 *   <li>SUPERADMIN — ALLOWED (manages ALL domains; the {@code domain} is the explicit PATH
 *       target, never a body field).</li>
 *   <li>ADMIN / MOD / USER — 403 (walled at the coarse {@code /bff/superadmin/**} gate AND
 *       the per-method SUPERADMIN gate).</li>
 * </ul>
 * {@code curated_by_subject} is stamped from the SUPERADMIN's {@code jwt.getSubject()}.
 */
@RestController
@RequestMapping("/bff/superadmin/service-store")
@Validated
public class ServiceCurationController {

    private final ServiceCurationService service;

    public ServiceCurationController(ServiceCurationService service) {
        this.service = service;
    }

    /** The Casdoor subject of the acting SUPERADMIN, from the validated JWT. */
    private static String subject(Authentication auth) {
        if (auth != null && auth.getPrincipal() instanceof Jwt jwt) {
            return jwt.getSubject();
        }
        return auth == null ? null : auth.getName();
    }

    // ── List the per-domain catalog (offered + withdrawn) for a {domain} (SUPERADMIN) ──
    @PreAuthorize("hasRole('SUPERADMIN')")
    @Operation(summary = "List", operationId = "serviceCurationList")
    @GetMapping("/{domain}")
    public Flux<ServiceCuration> list(
            @PathVariable @NotBlank @Size(max = 253) String domain) {
        return service.listForDomain(domain);
    }

    // ── Offer a service_key to a {domain}'s admins (SUPERADMIN) ──────────────────
    @PreAuthorize("hasRole('SUPERADMIN')")
    @Operation(summary = "Offer", operationId = "serviceCurationOffer")
    @PostMapping("/{domain}/offer")
    public Mono<ServiceCuration> offer(
            @PathVariable @NotBlank @Size(max = 253) String domain,
            @Valid @RequestBody ServiceCurationRequest body,
            Authentication auth) {
        return service.offer(domain, body.serviceKey(), subject(auth));
    }

    // ── Withdraw a service_key from a {domain}'s offered catalog (SUPERADMIN) ─────
    @PreAuthorize("hasRole('SUPERADMIN')")
    @Operation(summary = "Withdraw", operationId = "serviceCurationWithdraw")
    @PostMapping("/{domain}/withdraw")
    public Mono<ServiceCuration> withdraw(
            @PathVariable @NotBlank @Size(max = 253) String domain,
            @Valid @RequestBody ServiceCurationRequest body,
            Authentication auth) {
        return service.withdraw(domain, body.serviceKey(), subject(auth));
    }
}
