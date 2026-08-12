package net.hugmesh.adminbff.storage;

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
import net.hugmesh.commons.security.DomainRegistry;
import net.hugmesh.commons.security.PrincipalDomain;
import net.hugmesh.commons.web.ApiException;
import net.hugmesh.adminbff.web.dto.AssignServiceRequest;
import net.hugmesh.adminbff.web.dto.AttachPoolRequest;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * The NODE STORAGE admin surface — the console that ATTACHES additional storage to a mesh
 * node and ASSIGNS services to it. CLONES the
 * {@link net.hugmesh.adminbff.device.DeviceLicenseController} shape, with the
 * DELIBERATE DIVERGENCE that storage is ADMIN-CAPABLE (not superadmin-only).
 *
 * <h3>Authorization (defence-in-depth)</h3>
 * The coarse gate on {@code /bff/admin/**} is {@code hasAnyRole('ADMIN','SUPERADMIN')}. From
 * there EVERY method here is {@code hasAnyRole('ADMIN','SUPERADMIN')} too — but the real
 * authorization is the OWNERSHIP ALLOW/DENY matrix enforced DOWNSTREAM in
 * {@link NodeStorageService}:
 * <ul>
 *   <li>an ADMIN may read/mutate storage ONLY on own-domain ADMIN-owned nodes
 *       ({@link PrincipalDomain} residency + the node's {@code owner_type});</li>
 *   <li>any SUPERADMIN-owned node is SUPERADMIN-only — an ADMIN is DENIED (403);</li>
 *   <li>SUPERADMIN is unrestricted (unscoped reads, any node's mutations).</li>
 * </ul>
 * A DENY ({@link StorageAccessDeniedException}) maps to a 403; a validation failure
 * (unknown node, over-subscription, no-default) maps to a 422; the list view applies the
 * read scope so a brand admin literally cannot see another brand's rows. This controller
 * NEVER provisions storage itself — it only edits the desired-state rows the node-agent
 * reconcile + the 13b ApplicationSet consume.
 */
@RestController
@RequestMapping("/bff/admin/device-storage-pools")
@Validated
public class StoragePoolController {

    private static final Logger log = LoggerFactory.getLogger(StoragePoolController.class);

    private final NodeStorageService storage;
    private final NodeStorageExportService export;
    private final DomainRegistry domainRegistry;

    public StoragePoolController(NodeStorageService storage, NodeStorageExportService export,
                                 DomainRegistry domainRegistry) {
        this.storage = storage;
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
    @Operation(summary = "List", operationId = "storagePoolList")
    @GetMapping("")
    public Mono<Map<String, Object>> list(Authentication auth) {
        PrincipalDomain scope = scope(auth);
        return Mono.zip(
                storage.listPools(scope).collectList(),
                storage.listAssignments(scope).collectList(),
                (pools, assignments) -> {
                    Map<String, Object> out = new LinkedHashMap<>();
                    out.put("pools", pools);
                    out.put("assignments", assignments);
                    return out;
                });
    }

    // ── Attach a pool to a node (ADMIN own-domain admin-owned | SUPERADMIN) ──────
    @PreAuthorize("hasAnyRole('ADMIN','SUPERADMIN')")
    @Operation(summary = "Attach", operationId = "storagePoolAttach")
    @PostMapping("/{deviceId}/pools")
    public Mono<ResponseEntity<StoragePool>> attach(
            @PathVariable @NotBlank @Size(max = 36) String deviceId,
            @Valid @RequestBody AttachPoolRequest b, Authentication auth) {
        return storage.attachPool(deviceId, b.diskSerial(), b.poolPath(), b.reservedBytes(),
                        b.exclusive(), b.filesystem(), scope(auth), actor(auth))
                .doOnNext(p -> log.info("[storage-pools] attach by {} device={} -> pool {}",
                        actor(auth), deviceId, p.id()))
                .map(ResponseEntity::ok)
                .onErrorMap(StorageAccessDeniedException.class, e -> ApiException.forbidden(e.getMessage()))
                .onErrorMap(IllegalArgumentException.class, e -> ApiException.unprocessable(e.getMessage()));
    }

    // ── Detach a pool (ADMIN own | SUPERADMIN) ──────────────────────────────────
    @PreAuthorize("hasAnyRole('ADMIN','SUPERADMIN')")
    @Operation(summary = "Detach", operationId = "storagePoolDetach")
    @DeleteMapping("/pools/{poolId}")
    public Mono<ResponseEntity<Map<String, Object>>> detach(
            @PathVariable @NotBlank @Size(max = 36) String poolId, Authentication auth) {
        return storage.detachPool(poolId, scope(auth), actor(auth))
                .map(n -> ResponseEntity.ok(Map.<String, Object>of("detached", n)))
                .onErrorMap(StorageAccessDeniedException.class, e -> ApiException.forbidden(e.getMessage()))
                .onErrorMap(IllegalArgumentException.class, e -> ApiException.unprocessable(e.getMessage()));
    }

    // ── Assign a service to a pool (ADMIN own | SUPERADMIN; capacity-aware) ──────
    @PreAuthorize("hasAnyRole('ADMIN','SUPERADMIN')")
    @Operation(summary = "Assign", operationId = "storagePoolAssign")
    @PostMapping("/pools/{poolId}/assignments")
    public Mono<ResponseEntity<ServiceAssignment>> assign(
            @PathVariable @NotBlank @Size(max = 36) String poolId,
            @Valid @RequestBody AssignServiceRequest b, Authentication auth) {
        return storage.assignService(poolId, b.serviceName(), b.pvcName(), b.requestedBytes(),
                        scope(auth), actor(auth))
                .doOnNext(a -> log.info("[storage-pools] assign by {} pool={} service={} -> {}",
                        actor(auth), poolId, b.serviceName(), a.id()))
                .map(ResponseEntity::ok)
                .onErrorMap(StorageAccessDeniedException.class, e -> ApiException.forbidden(e.getMessage()))
                .onErrorMap(IllegalArgumentException.class, e -> ApiException.unprocessable(e.getMessage()));
    }

    // ── Revoke an assignment (ADMIN own | SUPERADMIN; CAS audit) ─────────────────
    @PreAuthorize("hasAnyRole('ADMIN','SUPERADMIN')")
    @Operation(summary = "Revoke", operationId = "storagePoolRevoke")
    @DeleteMapping("/assignments/{assignmentId}")
    public Mono<ResponseEntity<Map<String, Object>>> revoke(
            @PathVariable @NotBlank @Size(max = 36) String assignmentId, Authentication auth) {
        return storage.revokeAssignment(assignmentId, scope(auth), actor(auth))
                .map(n -> ResponseEntity.ok(Map.<String, Object>of("revoked", n)))
                .onErrorMap(StorageAccessDeniedException.class, e -> ApiException.forbidden(e.getMessage()))
                .onErrorMap(IllegalArgumentException.class, e -> ApiException.unprocessable(e.getMessage()));
    }

    // ── Signed per-node export (SUPERADMIN | internal mTLS) ─────────────────────
    /**
     * The signed PER-NODE node-storage export the node-agent reconcile (PR6) consumes,
     * addressed by the node's stable {@code machine_key_fp}. SAME SUPERADMIN |
     * internal-mTLS gate as the device-license export (no ROLE_USER/ROLE_ADMIN principal
     * reaches it; the per-node agent presents the SUPERADMIN service identity over mTLS).
     * The signed body carries ONLY THAT ONE node's active pools + assignments
     * [CONFIDENTIALITY], with a detached Ed25519 signature + a monotonic generation; an
     * unknown fp yields an EMPTY signed body (fail-closed, never a leaky error). A request
     * with no {@code node} is a clean 400.
     */
    @PreAuthorize("hasRole('SUPERADMIN')")
    @Operation(summary = "Export", operationId = "storagePoolExport")
    @GetMapping("/export")
    public Mono<StorageExportModels.SignedStorageExport> export(
            @RequestParam(value = "node", required = false) @Size(max = 128) String node) {
        if (node == null || node.isBlank()) {
            return Mono.error(ApiException.badRequest("'node' (the node machine_key_fp) is required"));
        }
        return export.exportNode(node);
    }
}
