package net.hugmesh.adminbff.capability;

import io.swagger.v3.oas.annotations.Operation;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;

import java.util.Map;

/**
 * The SERVICE-to-service DOMAIN CAPABILITY check — {@code /bff/internal/domain-capabilities/**}.
 * Mounted under {@code /bff/internal/**}, which {@code SecurityConfig} gates to
 * {@code ROLE_SERVICE} — satisfied by a Casdoor client-credentials SERVICE JWT or by the
 * in-cluster {@code X-Internal-Token} (promoted to a SERVICE principal), on top of the mTLS
 * transport and auth-core's {@code InternalTokenWebFilter}; NO human JWT reaches it. Mirrors
 * {@link net.hugmesh.adminbff.internalapi.InternalAccountController}'s wiring
 * exactly — same prefix, same trust boundary, same "in-cluster caller only, never exposed
 * publicly by the gateway" posture.
 *
 * <h3>The contract (for the not-yet-wired user-bff claim path)</h3>
 * {@code GET /bff/internal/domain-capabilities/{domain}/{capability}} → {@code 200
 * {"active": <bool>}}, ALWAYS 200 (never 404/403 for an absent or ungranted row — absence
 * IS a valid "false" answer, not an error). The caller (user-bff's mesh-device
 * registration/claim path) resolves {@code domain} SERVER-SIDE from its own validated
 * caller identity (the same issuer-derived {@code PrincipalDomain} pattern every other BFF
 * uses) before calling — this endpoint performs no cross-tenant check itself, exactly like
 * {@code InternalAccountController#sessionsForAccount}'s "account scoping is the caller's
 * responsibility" posture, because there is no untrusted principal at this internal hop.
 * {@code capability} for this feature is {@link DomainCapability#USER_MESH_DEVICES}.
 */
@RestController
@RequestMapping("/bff/internal/domain-capabilities")
@Validated
public class DomainCapabilityInternalController {

    private final DomainCapabilityService service;

    public DomainCapabilityInternalController(DomainCapabilityService service) {
        this.service = service;
    }

    /** {@code {"active": <bool>}} — the two-tier gate result for (domain, capability).
     *  Fail-closed: any lookup error resolves to {@code active:false} (see
     *  {@link DomainCapabilityService#isActive}), never a 5xx that could be mistaken for
     *  "allowed" by a careless caller. */
    @Operation(summary = "Active", operationId = "domainCapabilityInternalActive")
    @GetMapping("/{domain}/{capability}")
    public Mono<Map<String, Boolean>> active(
            @PathVariable @NotBlank @Size(max = 255) String domain,
            @PathVariable @NotBlank @Size(max = 64) String capability) {
        return service.isActive(domain, capability).map(active -> Map.of("active", active));
    }
}
