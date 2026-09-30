package net.hugmesh.adminbff.egressvpn;

import io.swagger.v3.oas.annotations.Operation;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;

/**
 * INTERNAL MIRROR of {@code GET /bff/admin/egress-vpn/export}
 * ({@link EgressVpnController#export}) for node agents — operator
 * decision 89b = A (2026-09-23, hugmesh-admin-bff-api#6): nodes hold the shared
 * {@code X-Internal-Token}, which {@code SecurityConfig} promotes to {@code ROLE_SERVICE} on
 * {@code /bff/internal/**} only. The SUPERADMIN twin stays where it is for the console.
 *
 * <p>Same export service method, same query parameters, same 400 rules, so the signed body is
 * byte-identical to the twin's for the same data ({@code NodeExportInternalMirrorTest} pins it).
 * NO {@code @PreAuthorize} here on purpose: the role hierarchy has no edge from SERVICE to
 * SUPERADMIN, so a copied {@code hasRole('SUPERADMIN')} would refuse the only caller this exists
 * for. The coarse {@code /bff/internal/**} rule is the gate.
 */
@RestController
@RequestMapping("/bff/internal/egress-vpn")
@Validated
public class EgressVpnInternalExportController {

    private final VpnExportService export;

    public EgressVpnInternalExportController(VpnExportService export) {
        this.export = export;
    }

    /** {@code GET /bff/internal/egress-vpn/export?node=<fp>} — see the twin. */
    @Operation(summary = "Export (internal mirror)", operationId = "egressVpnInternalExport")
    @GetMapping("/export")
    public Mono<VpnExportModels.SignedVpnExport> export(
            @RequestParam(value = "node") @NotBlank @Size(max = 128) String node) {
        return export.exportNode(node);
    }
}
