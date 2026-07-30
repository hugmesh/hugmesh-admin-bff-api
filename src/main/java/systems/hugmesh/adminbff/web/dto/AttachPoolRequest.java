package systems.hugmesh.adminbff.web.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Positive;
import jakarta.validation.constraints.Size;
import org.jspecify.annotations.Nullable;

/**
 * Body for {@code POST /bff/admin/device-storage-pools/{deviceId}/pools} (ADMIN|SUPERADMIN)
 * — registers ADDITIONAL storage attached to a mesh node (schema 085). The
 * {@code @NotBlank}/{@code @Positive} guards make a malformed attach a clean 400 BEFORE any
 * write; the OWNERSHIP ALLOW/DENY gate (the node must be own-domain ADMIN-owned for an
 * ADMIN; SUPERADMIN unrestricted) is enforced in
 * {@link systems.hugmesh.adminbff.storage.NodeStorageService} (DENY -> 403), and the
 * residency-stamped {@code domain} comes from the node, never the caller [FIX-NODEFAULT].
 *
 * <ul>
 *   <li>{@code diskSerial} — the stable per-disk identity (serial/wwn); re-attaching the
 *       same disk on the same node is idempotent.</li>
 *   <li>{@code poolPath} — the node-local provisioner path the {@code nodePathMap} maps.</li>
 *   <li>{@code reservedBytes} — the capacity claim (the node-agent's df is authoritative).</li>
 *   <li>{@code exclusive} — one service per pool (UI defaults true for video).</li>
 *   <li>{@code filesystem} — optional descriptor (ext4 / xfs / ...).</li>
 * </ul>
 */
public record AttachPoolRequest(
        @NotBlank(message = "diskSerial is required")
        @Size(max = 128, message = "diskSerial is too long")
        String diskSerial,

        @NotBlank(message = "poolPath is required")
        @Size(max = 512, message = "poolPath is too long")
        String poolPath,

        @Positive(message = "reservedBytes must be > 0")
        long reservedBytes,

        boolean exclusive,

        @Size(max = 32, message = "filesystem is too long")
        @Nullable
        String filesystem) {
}
