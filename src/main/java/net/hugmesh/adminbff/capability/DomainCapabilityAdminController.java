package net.hugmesh.adminbff.capability;

import io.swagger.v3.oas.annotations.Operation;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import net.hugmesh.commons.security.DomainRegistry;
import net.hugmesh.commons.security.PrincipalDomain;
import net.hugmesh.commons.web.ApiException;
import net.hugmesh.adminbff.web.dto.DomainCapabilityEnabledRequest;
import net.hugmesh.adminbff.web.dto.DomainCapabilityGrantedRequest;

/**
 * The DOMAIN CAPABILITY GATE admin surface — {@code /bff/admin/domain-capabilities/**}. One
 * route family shared by two DIFFERENT role tiers, distinguished per-method (mirrors how
 * {@code /bff/admin/**} already hosts both plain-ADMIN surfaces like
 * {@code MastodonAppearanceDefaultAdminController} and SUPERADMIN-only ones — the coarse
 * {@code hasAnyRole('ADMIN','SUPERADMIN')} path gate in {@code SecurityConfig} is
 * defence-in-depth; the REAL gate is the per-method {@code @PreAuthorize} below):
 *
 * <ul>
 *   <li>{@link #list} — {@code GET ""}: {@code hasAnyRole('ADMIN','SUPERADMIN')}, but
 *       SERVICE-scoped ({@link DomainCapabilityService#listForScope}) exactly like
 *       {@code RadioDeviceController#list}: a SUPERADMIN sees every domain's gate rows
 *       (the "domains × capability" superadmin view); a domain ADMIN sees ONLY their own
 *       domain's rows (never the {@code ' global'} sentinel, never another brand) — which
 *       is what lets the admin UI render its own toggle + "waiting on a grant" state
 *       without a second bespoke read endpoint.</li>
 *   <li>{@link #setGranted} — {@code PUT /{domain}/{capability}}: SUPERADMIN ONLY. The
 *       {@code granted} key; on {@code domain == ' global'} this IS the platform-wide
 *       kill (documented on {@link DomainCapability#GLOBAL_DOMAIN}). An ADMIN JWT never
 *       even reaches the body — the role gate alone enforces "cannot touch granted".</li>
 *   <li>{@link #setEnabled} — {@code PUT /{domain}/{capability}/enabled}: ADMIN (own
 *       domain only) or SUPERADMIN (any domain, including {@code ' global'}). The
 *       own-domain + never-the-global-sentinel check is enforced IN-BODY (not by the
 *       role gate alone, since both roles reach this method) against the caller's
 *       validated-issuer {@link PrincipalDomain}.</li>
 * </ul>
 */
@RestController
@RequestMapping("/bff/admin/domain-capabilities")
@Validated
public class DomainCapabilityAdminController {

    private final DomainCapabilityService service;
    private final DomainRegistry domainRegistry;

    public DomainCapabilityAdminController(DomainCapabilityService service,
                                           DomainRegistry domainRegistry) {
        this.service = service;
        this.domainRegistry = domainRegistry;
    }

    private PrincipalDomain scope(Authentication auth) {
        return PrincipalDomain.of(auth, domainRegistry);
    }

    private static String actor(Authentication auth) {
        return auth == null ? "admin" : auth.getName();
    }

    /** SUPERADMIN sees every domain's gate rows; a domain ADMIN sees only their own. */
    @PreAuthorize("hasAnyRole('ADMIN','SUPERADMIN')")
    @Operation(summary = "List", operationId = "domainCapabilityList")
    @GetMapping("")
    public Flux<DomainCapability> list(Authentication auth) {
        return service.listForScope(scope(auth));
    }

    /** SUPERADMIN-only: the {@code granted} key ({@code ' global'} == the platform-wide
     *  kill). */
    @PreAuthorize("hasRole('SUPERADMIN')")
    @Operation(summary = "Set granted", operationId = "domainCapabilitySetGranted")
    @PutMapping("/{domain}/{capability}")
    public Mono<DomainCapability> setGranted(
            @PathVariable @NotBlank @Size(max = 255) String domain,
            @PathVariable @NotBlank @Size(max = 64) String capability,
            @Valid @RequestBody DomainCapabilityGrantedRequest body, Authentication auth) {
        return service.grant(domain, capability, body.granted(), actor(auth));
    }

    /** ADMIN (own domain only) or SUPERADMIN (any domain): the {@code enabled} key. An
     *  ADMIN can never touch {@code granted}, another domain, or the {@code ' global'}
     *  sentinel — enforced here since both roles share this method. */
    @PreAuthorize("hasAnyRole('ADMIN','SUPERADMIN')")
    @Operation(summary = "Set enabled", operationId = "domainCapabilitySetEnabled")
    @PutMapping("/{domain}/{capability}/enabled")
    public Mono<DomainCapability> setEnabled(
            @PathVariable @NotBlank @Size(max = 255) String domain,
            @PathVariable @NotBlank @Size(max = 64) String capability,
            @Valid @RequestBody DomainCapabilityEnabledRequest body, Authentication auth) {
        PrincipalDomain scope = scope(auth);
        if (!scope.superadmin()) {
            if (DomainCapability.GLOBAL_DOMAIN.equals(domain)) {
                return Mono.error(ApiException.forbidden(
                        "only a superadmin may touch the ' global' sentinel"));
            }
            if (!domain.equals(scope.domain())) {
                return Mono.error(ApiException.forbidden(
                        "an admin may only enable a capability for their own domain"));
            }
        }
        return service.enable(domain, capability, body.enabled(), actor(auth));
    }
}
