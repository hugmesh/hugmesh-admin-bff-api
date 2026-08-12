package net.hugmesh.adminbff.web.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import org.jspecify.annotations.Nullable;

/**
 * Body for {@code POST /bff/internal/device-enrollment/self-report} — a node's one-shot
 * LIVENESS self-report (mTLS, NO JWT). It carries ONLY reconciliation hints; there are NO
 * authorizing fields (no owner, no domain, no license, no role) by design — a node self-claim
 * is spoofable, so it can never confer access. The trust gate is headscale + the SUPERADMIN
 * assignment; this just lets a superadmin cross-check the node's self-claim.
 *
 * <ul>
 *   <li>{@code machineKeyFp} — the fingerprint the NODE believes it baked (the only required
 *       field; UNIQUE in {@code device_enrollment}).</li>
 *   <li>{@code hostname} / {@code meshId} / {@code tailnetId} — optional reconciliation hints.</li>
 * </ul>
 */
public record SelfReportRequest(
        @NotBlank(message = "machineKeyFp is required")
        @Size(max = 128, message = "machineKeyFp is too long")
        String machineKeyFp,

        @Size(max = 253, message = "hostname is too long")
        @Nullable
        String hostname,

        @Size(max = 64, message = "meshId is too long")
        @Nullable
        String meshId,

        @Size(max = 128, message = "tailnetId is too long")
        @Nullable
        String tailnetId) {
}
