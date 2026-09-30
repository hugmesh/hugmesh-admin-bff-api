package net.hugmesh.adminbff.domainregistry;

import io.swagger.v3.oas.annotations.Operation;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;
import net.hugmesh.adminbff.web.dto.DomainReconcileAckRequest;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * The NODE AGENT's side of the domain registry — hugmesh-generator
 * {@code specs/usr/sbin/hugmesh-domain-reconcile} (operator decision 89b = A, 2026-09-23:
 * "Give nodes the shared internal token").
 *
 * <h3>Why a second controller</h3>
 * The agent authenticates with the shared {@code X-Internal-Token}, which {@code SecurityConfig}
 * promotes to {@code ROLE_SERVICE} on {@code /bff/internal/**} and nowhere else. The signed export
 * lives at {@code GET /bff/admin/domains/export}, behind {@code hasRole('SUPERADMIN')}; the role
 * hierarchy has no edge from SERVICE to SUPERADMIN (deliberately, so the shared token is never an
 * admin bypass), so the agent could never fetch it. This controller MIRRORS it under the internal
 * prefix, delegating to the SAME {@link DomainRegistryExportService#exportRegistry(String)} with
 * the same parameter, so the signed bytes are identical for the same data. It carries NO
 * {@code @PreAuthorize}: a copied {@code hasRole('SUPERADMIN')} would 403 the only caller this
 * exists for. The coarse {@code /bff/internal/**} rule is the gate.
 *
 * <p>It also hosts the agent's report-back, {@code POST .../{clusterDomain}/reconcile-ack}, at
 * exactly the path the agent already calls ({@code ack_generation}, hugmesh-domain-reconcile
 * :478-486 on origin/main 06bd65c5).
 *
 * <p>The generator half (point {@code fetch_export} at {@code /bff/internal/domains/export}, add
 * the token header to both curls, put the token and {@code BFF_ACK_URL} in {@code node.env}) is
 * hugmesh-generator's, not this repo's.
 */
@RestController
@RequestMapping("/bff/internal/domains")
@Validated
public class DomainRegistryInternalController {

    private static final Logger log = LoggerFactory.getLogger(DomainRegistryInternalController.class);

    private final DomainRegistryService service;
    private final DomainRegistryExportService export;

    public DomainRegistryInternalController(DomainRegistryService service,
                                            DomainRegistryExportService export) {
        this.service = service;
        this.export = export;
    }

    /**
     * {@code GET /bff/internal/domains/export[?node=<fp>]} — the internal mirror of
     * {@code GET /bff/admin/domains/export}: the same signed cross-domain body, the same optional
     * provenance-only {@code node} parameter.
     */
    @Operation(summary = "Export (internal mirror)", operationId = "domainRegistryInternalExport")
    @GetMapping("/export")
    public Mono<DomainExportModels.SignedDomainExport> export(
            @RequestParam(value = "node", required = false) @Size(max = 128) String node) {
        return export.exportRegistry(node);
    }

    /**
     * {@code POST /bff/internal/domains/{clusterDomain}/reconcile-ack} — body
     * {@code {"caProvisioned": <ignored>, "appsetRegistered": <bool>, "generation": <long>}}.
     * {@code 200 {"clusterDomain", "applied"}}: {@code applied:true} when the ack advanced the row,
     * {@code false} when its generation was not newer than the stored one (a replay or a late
     * ack — a normal outcome for a looping agent, not an error). 404 for an unregistered domain.
     */
    @Operation(summary = "Reconcile ack", operationId = "domainRegistryInternalReconcileAck")
    @PostMapping("/{clusterDomain}/reconcile-ack")
    public Mono<Map<String, Object>> reconcileAck(
            @PathVariable @NotBlank @Size(max = 253) String clusterDomain,
            @Valid @RequestBody DomainReconcileAckRequest body) {
        return service.recordReconcileAck(clusterDomain, body.appsetRegistered(), body.generation())
                .map(applied -> ackResponse(clusterDomain, body, applied));
    }

    private static Map<String, Object> ackResponse(String clusterDomain,
                                                   DomainReconcileAckRequest body,
                                                   boolean applied) {
        if (applied) {
            log.info("[domain-registry] reconcile-ack cluster_domain={} appset={} gen={}",
                    clusterDomain, body.appsetRegistered(), body.generation());
        }
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("clusterDomain", clusterDomain);
        out.put("applied", applied);
        return out;
    }
}
