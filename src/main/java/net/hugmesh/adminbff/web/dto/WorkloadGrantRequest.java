package net.hugmesh.adminbff.web.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import org.jspecify.annotations.Nullable;

/**
 * Body for {@code POST /bff/superadmin/workloads/grants} (SUPERADMIN) — issue a READ_ONLY
 * WORKLOAD CONSOLE grant LEASE for {@code grantee} in {@code targetDomain}. DECISION 4: the
 * grant is status/topology/metrics only; {@code logAccess} is a SEPARATE opt-in (defaults
 * FALSE if omitted); {@code ttlHours} defaults to the configured ~24h if omitted/zero. The
 * grant is always READ_ONLY (the schema CHECK forbids anything else), so there is no
 * access-level field.
 */
public record WorkloadGrantRequest(
        @NotBlank(message = "grantee is required")
        @Size(max = 400, message = "grantee is too long")
        String grantee,

        @NotBlank(message = "targetDomain is required")
        @Size(max = 64, message = "targetDomain is too long")
        String targetDomain,

        boolean logAccess,

        @Nullable
        Long ttlHours) {
}
