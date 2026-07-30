package systems.hugmesh.adminbff.cloudbackup;

import java.time.Instant;

/**
 * A single {@code backup_destination} row — the per-domain destination CONFIG (schema 160).
 * At most one row per brand (UNIQUE on {@code domain}); the PUT endpoint upserts it.
 *
 * <ul>
 *   <li>{@code kind} — {@code object_store} (S3/MinIO) or {@code node_storage} (the superadmin
 *       device-attached FDE volume = a {@code node_storage_pool} reference).</li>
 *   <li>{@code destinationRef} — the bucket/endpoint (object_store) or the
 *       {@code node_storage_pool} id (node_storage). NEVER credentials.</li>
 *   <li>{@code secretRef} — the object-store credentials Secret REFERENCE (ESO/Vault); null
 *       for node_storage. NEVER the credential bytes.</li>
 *   <li>{@code domain} — the brand this config belongs to (stamped from the validated issuer,
 *       the scoped-admin read predicate).</li>
 * </ul>
 */
public record BackupDestination(
        String id,
        BackupDestinationKind kind,
        String destinationRef,
        String secretRef,
        String domain,
        String updatedBy,
        Instant createdAt,
        Instant updatedAt) {
}
