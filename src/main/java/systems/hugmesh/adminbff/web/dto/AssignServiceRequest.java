package systems.hugmesh.adminbff.web.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Positive;
import jakarta.validation.constraints.Size;

/**
 * Body for {@code POST /bff/admin/device-storage-pools/pools/{poolId}/assignments}
 * (ADMIN|SUPERADMIN) — places a service onto a pool's node (schema 085). The pool is the
 * path variable; this body carries the service identity, its PVC, and the requested slice.
 * The OWNERSHIP gate (on the pool's NODE) + the over-subscription / exclusivity check are
 * enforced in {@link systems.hugmesh.adminbff.storage.NodeStorageService} (DENY -> 403,
 * over-subscription -> 422); the residency-stamped {@code domain} comes from the pool, never
 * the caller [FIX-NODEFAULT].
 *
 * <ul>
 *   <li>{@code serviceName} — the workload being placed (the Kustomize patch keys on it).</li>
 *   <li>{@code pvcName} — the PVC the patch binds to the node-pinned PV.</li>
 *   <li>{@code requestedBytes} — the slice of the pool reserved for this service.</li>
 * </ul>
 */
public record AssignServiceRequest(
        @NotBlank(message = "serviceName is required")
        @Size(max = 253, message = "serviceName is too long")
        String serviceName,

        @NotBlank(message = "pvcName is required")
        @Size(max = 253, message = "pvcName is too long")
        String pvcName,

        @Positive(message = "requestedBytes must be > 0")
        long requestedBytes) {
}
