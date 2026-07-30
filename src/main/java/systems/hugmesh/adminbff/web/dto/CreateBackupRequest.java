package systems.hugmesh.adminbff.web.dto;

import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import org.jspecify.annotations.Nullable;

import java.util.List;

/**
 * Body for {@code POST /bff/admin/cloud-backups} (DOMAIN scope, ADMIN/SUPERADMIN) and the
 * {@code scope:"TOTAL"} variant via {@code POST /bff/superadmin/cloud-backups/total}
 * (SUPERADMIN-only). The {@code @NotNull}/{@code @NotEmpty} guards make a malformed request a
 * clean 400 BEFORE any write; the residency-derived {@code domain} + {@code createdBy} are
 * stamped server-side (never the body), so this carries only the request intent.
 *
 * <ul>
 *   <li>{@code setKey} — the LOGICAL backup identity (version-chain key); blank -> a derived
 *       default keyed on scope+domain.</li>
 *   <li>{@code services} — the selected running services (the per-service menu); non-empty.</li>
 *   <li>{@code destinationKind} — {@code object_store} or {@code node_storage}.</li>
 *   <li>{@code destinationRef} — the bucket/endpoint (object_store) or node_storage_pool id.</li>
 *   <li>{@code encryptionMeta} — a repo / age-recipient REFERENCE JSON; NEVER the key bytes.</li>
 * </ul>
 *
 * <p>NOTE: {@code scope} is NOT a body field on the per-domain {@code POST
 * /bff/admin/cloud-backups} (it is always DOMAIN there). The TOTAL scope is reached ONLY via
 * the SUPERADMIN-only {@code /bff/superadmin/cloud-backups/total} endpoint, so a scoped admin
 * can never request a TOTAL backup by setting a body field.
 */
public record CreateBackupRequest(
        @Size(max = 128, message = "setKey is too long")
        @Nullable
        String setKey,

        @NotEmpty(message = "at least one service is required")
        @Size(max = 64, message = "too many services selected")
        List<@Size(max = 253, message = "a service key is too long") String> services,

        @NotNull(message = "destinationKind is required (object_store or node_storage)")
        @Size(max = 24, message = "destinationKind is too long")
        String destinationKind,

        @NotNull(message = "destinationRef is required")
        @Size(max = 512, message = "destinationRef is too long")
        String destinationRef,

        @Size(max = 2048, message = "encryptionMeta is too long")
        @Nullable
        String encryptionMeta) {
}
