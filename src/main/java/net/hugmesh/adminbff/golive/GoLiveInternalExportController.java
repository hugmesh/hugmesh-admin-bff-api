package net.hugmesh.adminbff.golive;

import io.swagger.v3.oas.annotations.Operation;

import jakarta.validation.constraints.Size;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;

/**
 * INTERNAL MIRROR of {@code GET /bff/admin/go-live/export}
 * ({@link GoLiveController#export}) for node agents — operator
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
@RequestMapping("/bff/internal/go-live")
@Validated
public class GoLiveInternalExportController {

    private final GoLiveExportService export;

    public GoLiveInternalExportController(GoLiveExportService export) {
        this.export = export;
    }

    /** {@code GET /bff/internal/go-live/export[?node=<fp>]} — see the twin. */
    @Operation(summary = "Export (internal mirror)", operationId = "goLiveInternalExport")
    @GetMapping("/export")
    public Mono<GoLiveExportModels.SignedGoLiveExport> export(
            @RequestParam(value = "node", required = false) @Size(max = 128) String node) {
        return export.exportIntents(node);
    }
}
