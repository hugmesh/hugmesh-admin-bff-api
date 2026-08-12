package net.hugmesh.adminbff.web.dto;

import jakarta.validation.constraints.Size;
import org.jspecify.annotations.Nullable;

/**
 * Body for {@code PUT /bff/admin/domains/{clusterDomain}} (SUPERADMIN) — updates the
 * MUTABLE descriptors of an existing {@code domain_registry} row (schema 012). The
 * {@code clusterDomain} natural key comes from the PATH and is IMMUTABLE (so is the
 * row's {@code id}, {@code created_at} and {@code created_by_subject}) — only the brand
 * descriptors and the {@code enabled} desired-state flag change. A domain is disabled by
 * sending {@code enabled:false} (the SOFT-DISABLE — there is no hard delete).
 */
public record UpdateDomainRequest(
        @Size(max = 64, message = "brand is too long")
        @Nullable
        String brand,

        @Size(max = 255, message = "org is too long")
        @Nullable
        String org,

        @Size(max = 512, message = "caRef is too long")
        @Nullable
        String caRef,

        @Size(max = 64, message = "nsPrefix is too long")
        @Nullable
        String nsPrefix,

        @Size(max = 255, message = "casdoorOrg is too long")
        @Nullable
        String casdoorOrg,

        @Size(max = 64, message = "meshTag is too long")
        @Nullable
        String meshTag,

        /** Desired-state on/off. {@code null} (omitted) leaves the current value
         *  unchanged; {@code false} is the SOFT-DISABLE. */
        @Nullable
        Boolean enabled) {
}
