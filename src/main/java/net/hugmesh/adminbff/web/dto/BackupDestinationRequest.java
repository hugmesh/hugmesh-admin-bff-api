package net.hugmesh.adminbff.web.dto;

import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import org.jspecify.annotations.Nullable;

/**
 * Body for {@code PUT /bff/admin/cloud-backups/destinations} (ADMIN/SUPERADMIN) — upsert the
 * per-domain backup destination CONFIG. The {@code domain} is stamped server-side from the
 * validated issuer (a scoped admin's own brand), never the body, so this carries only the
 * destination intent.
 *
 * <ul>
 *   <li>{@code kind} — {@code object_store} (S3/MinIO) or {@code node_storage} (the superadmin
 *       device-attached FDE volume = a node_storage_pool reference).</li>
 *   <li>{@code destinationRef} — the bucket/endpoint (object_store) or the node_storage_pool
 *       id (node_storage). NEVER credentials.</li>
 *   <li>{@code secretRef} — the object-store credentials Secret REFERENCE (ESO/Vault); null
 *       for node_storage. NEVER the credential bytes.</li>
 *   <li>{@code targetDomain} — SUPERADMIN-ONLY: the brand to configure; ignored for a scoped
 *       admin (always their own brand).</li>
 * </ul>
 */
public record BackupDestinationRequest(
        @NotNull(message = "kind is required (object_store or node_storage)")
        @Size(max = 24, message = "kind is too long")
        String kind,

        @NotNull(message = "destinationRef is required")
        @Size(max = 512, message = "destinationRef is too long")
        String destinationRef,

        @Size(max = 512, message = "secretRef is too long")
        @Nullable
        String secretRef,

        @Size(max = 64, message = "targetDomain is too long")
        @Nullable
        String targetDomain) {
}
