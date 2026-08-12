package net.hugmesh.adminbff.desktop;

import io.swagger.v3.oas.annotations.Operation;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * The DESKTOP SUDO ENTITLEMENT read — the endpoint the IdP/desktop consults to decide
 * whether to mint the {@code desktop-sudo} SSO claim for a (subject, device). Mounted under
 * {@code /bff/internal/**} (the in-cluster node-to-BFF surface): NO human JWT — {@code
 * SecurityConfig} gates the prefix to {@code ROLE_SERVICE}, which the IdP satisfies with the
 * in-cluster {@code X-Internal-Token}, on top of the mTLS transport in production
 * ({@code server.ssl.client-auth=need} — only a caller holding a cert chaining to the cluster
 * CA completes the handshake). The prefix is NOT unreachable from outside — the fe-gateway's
 * {@code /bff/**} route forwards to it — which is precisely why the SERVICE floor, not the
 * transport, is the boundary for this per-(subject, device) sudo-state read.
 *
 * <p>The endpoint confers NOTHING by itself — it only REPORTS whether an active grant exists
 * (the source of truth the IdP turns into a claim). A revoked / absent grant returns
 * {@code allowed=false} (DEFAULT NONE). Keyed by subject+device, NOT brand-scoped (the IdP is
 * a trusted internal caller, not an admin).
 */
@RestController
@RequestMapping("/bff/internal/desktop/sudo")
@Validated
public class DesktopSudoEntitlementController {

    private final DesktopSudoGrantService service;

    public DesktopSudoEntitlementController(DesktopSudoGrantService service) {
        this.service = service;
    }

    /**
     * The sudo entitlement for one (subject, device): {@code {allowed, subject, deviceId,
     * grantId?, domain?}}. {@code allowed=true} iff an ACTIVE grant exists — the IdP mints
     * the {@code desktop-sudo} claim only then. Fail-closed: anything else (no grant /
     * revoked) is {@code allowed=false}.
     */
    @Operation(summary = "Entitlement", operationId = "desktopSudoEntitlementEntitlement")
    @GetMapping("/entitlement")
    public Mono<Map<String, Object>> entitlement(
            @RequestParam @NotBlank @Size(max = 400) String subject,
            @RequestParam @NotBlank @Size(max = 36) String deviceId) {
        return service.entitlement(subject, deviceId)
                .map(g -> {
                    Map<String, Object> out = new LinkedHashMap<>();
                    out.put("allowed", true);
                    out.put("subject", g.subject());
                    out.put("deviceId", g.deviceId());
                    out.put("grantId", g.id());
                    out.put("domain", g.domain());
                    out.put("generation", g.generation());
                    return out;
                })
                .defaultIfEmpty(deny(subject, deviceId));
    }

    private static Map<String, Object> deny(String subject, String deviceId) {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("allowed", false);
        out.put("subject", subject);
        out.put("deviceId", deviceId);
        return out;
    }
}
