package systems.hugmesh.adminbff.radio;

import io.swagger.v3.oas.annotations.Operation;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Mono;
import systems.hugmesh.commons.security.DomainRegistry;
import systems.hugmesh.commons.security.PrincipalDomain;
import systems.hugmesh.commons.web.ApiException;
import systems.hugmesh.adminbff.web.dto.AttachRadioRequest;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * The NODE RADIO admin surface — the console that ATTACHES a Meshtastic LoRa radio to a mesh
 * node for the meshbridge optional service (the mesh&lt;-&gt;Matrix bridge, built in
 * parallel). CLONES the {@link systems.hugmesh.adminbff.storage.StoragePoolController}
 * shape, KEEPING its DELIBERATE DIVERGENCE that the surface is ADMIN-CAPABLE (not
 * superadmin-only).
 *
 * <h3>Authorization (defence-in-depth)</h3>
 * The coarse gate on {@code /bff/admin/**} is {@code hasAnyRole('ADMIN','SUPERADMIN')}. From
 * there EVERY method here is {@code hasAnyRole('ADMIN','SUPERADMIN')} too — but the real
 * authorization is the OWNERSHIP ALLOW/DENY matrix enforced DOWNSTREAM in
 * {@link NodeRadioService}:
 * <ul>
 *   <li>an ADMIN may read/mutate radios ONLY on own-domain ADMIN-owned nodes
 *       ({@link PrincipalDomain} residency + the node's {@code owner_type});</li>
 *   <li>any SUPERADMIN-owned node is SUPERADMIN-only — an ADMIN is DENIED (403);</li>
 *   <li>SUPERADMIN is unrestricted (unscoped reads, any node's mutations).</li>
 * </ul>
 * A DENY ({@link RadioAccessDeniedException}) maps to a 403; a validation failure (unknown
 * node, a MIXED per-transport shape) maps to a 422; a malformed field is a bean-validation
 * 400 before the service is reached; the list view applies the read scope so a brand admin
 * literally cannot see another brand's rows. This controller NEVER bridges anything itself
 * — it only edits the desired-state rows the on-node meshbridge reconcile agent consumes
 * via the signed per-node export.
 */
@RestController
@RequestMapping("/bff/admin/device-radios")
@Validated
public class RadioDeviceController {

    private static final Logger log = LoggerFactory.getLogger(RadioDeviceController.class);

    private final NodeRadioService radios;
    private final NodeRadioExportService export;
    private final DomainRegistry domainRegistry;

    public RadioDeviceController(NodeRadioService radios, NodeRadioExportService export,
                                 DomainRegistry domainRegistry) {
        this.radios = radios;
        this.export = export;
        this.domainRegistry = domainRegistry;
    }

    private PrincipalDomain scope(Authentication auth) {
        return PrincipalDomain.of(auth, domainRegistry);
    }

    private static String actor(Authentication auth) {
        return auth == null ? "admin" : auth.getName();
    }

    // ── List (ADMIN own-domain RO via scope; SUPERADMIN all) ────────────────────
    @PreAuthorize("hasAnyRole('ADMIN','SUPERADMIN')")
    @Operation(summary = "List", operationId = "deviceRadioList")
    @GetMapping("")
    public Mono<Map<String, Object>> list(Authentication auth) {
        PrincipalDomain scope = scope(auth);
        return radios.listRadios(scope).collectList()
                .map(rows -> {
                    Map<String, Object> out = new LinkedHashMap<>();
                    out.put("radios", rows);
                    return out;
                });
    }

    // ── Attach a radio to a node (ADMIN own-domain admin-owned | SUPERADMIN) ─────
    @PreAuthorize("hasAnyRole('ADMIN','SUPERADMIN')")
    @Operation(summary = "Attach", operationId = "deviceRadioAttach")
    @PostMapping("/{deviceId}/radios")
    public Mono<ResponseEntity<RadioDevice>> attach(
            @PathVariable @NotBlank @Size(max = 36) String deviceId,
            @Valid @RequestBody AttachRadioRequest b, Authentication auth) {
        return radios.attachRadio(deviceId, b.transport(), b.serialPath(), b.host(), b.port(),
                        b.topicRoot(), b.channelName(), b.gatewayNodeId(), b.radioId(),
                        b.meshChannel(), scope(auth), actor(auth))
                .doOnNext(r -> log.info("[device-radios] attach by {} device={} -> radio {}",
                        actor(auth), deviceId, r.id()))
                .map(ResponseEntity::ok)
                .onErrorMap(RadioAccessDeniedException.class, e -> ApiException.forbidden(e.getMessage()))
                .onErrorMap(IllegalArgumentException.class, e -> ApiException.unprocessable(e.getMessage()));
    }

    // ── Detach a radio (ADMIN own | SUPERADMIN) ─────────────────────────────────
    @PreAuthorize("hasAnyRole('ADMIN','SUPERADMIN')")
    @Operation(summary = "Detach", operationId = "deviceRadioDetach")
    @DeleteMapping("/radios/{radioId}")
    public Mono<ResponseEntity<Map<String, Object>>> detach(
            @PathVariable @NotBlank @Size(max = 36) String radioId, Authentication auth) {
        return radios.detachRadio(radioId, scope(auth), actor(auth))
                .map(n -> ResponseEntity.ok(Map.<String, Object>of("detached", n)))
                .onErrorMap(RadioAccessDeniedException.class, e -> ApiException.forbidden(e.getMessage()))
                .onErrorMap(IllegalArgumentException.class, e -> ApiException.unprocessable(e.getMessage()));
    }

    // ── Signed per-node export (SUPERADMIN | internal mTLS) ─────────────────────
    /**
     * The signed PER-NODE node-radio export the FUTURE on-node meshbridge reconcile agent
     * consumes, addressed by the node's stable {@code machine_key_fp}. SAME SUPERADMIN |
     * internal-mTLS gate as the device-license/storage exports (no ROLE_USER/ROLE_ADMIN
     * principal reaches it; the per-node agent presents the SUPERADMIN service identity
     * over mTLS). The signed body carries ONLY THAT ONE node's active radios
     * [CONFIDENTIALITY], with a detached Ed25519 signature + a monotonic generation; an
     * unknown fp yields an EMPTY signed body (fail-closed, never a leaky error). A request
     * with no {@code node} is a clean 400.
     */
    @PreAuthorize("hasRole('SUPERADMIN')")
    @Operation(summary = "Export", operationId = "deviceRadioExport")
    @GetMapping("/export")
    public Mono<RadioExportModels.SignedRadioExport> export(
            @RequestParam(value = "node", required = false) @Size(max = 128) String node) {
        if (node == null || node.isBlank()) {
            return Mono.error(ApiException.badRequest("'node' (the node machine_key_fp) is required"));
        }
        return export.exportNode(node);
    }
}
