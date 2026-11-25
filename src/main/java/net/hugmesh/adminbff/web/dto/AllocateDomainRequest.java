package net.hugmesh.adminbff.web.dto;

import jakarta.validation.constraints.Size;
import org.jspecify.annotations.Nullable;

/**
 * Body for {@code POST /bff/admin/domains/{clusterDomain}/allocate} (SUPERADMIN) — the
 * "allocate now" action for a domain registered before decision 29 (hugmesh-admin-bff-api#6
 * item 5, operator decision 89c = A).
 *
 * <p>{@code nsPrefix} is REQUIRED when the row has no slug yet (it is then set once, validated
 * like a create) and must be omitted or equal to the stored slug otherwise. The MCS pair is never
 * supplied by the caller: it comes from the allocator.
 */
public record AllocateDomainRequest(
        @Size(max = 64, message = "nsPrefix is too long")
        @Nullable
        String nsPrefix) {
}
