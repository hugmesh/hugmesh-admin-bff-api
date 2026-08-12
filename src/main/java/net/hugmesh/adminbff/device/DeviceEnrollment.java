package net.hugmesh.adminbff.device;

import java.time.Instant;

/**
 * One {@code device_enrollment} row — a LIVENESS self-report a node POSTs at boot (mTLS, NO
 * JWT). It records the fingerprint the NODE believes it baked plus reconciliation hints
 * (hostname/meshId/tailnetId) so a superadmin can cross-check the node's self-claim against
 * what headscale reports when picking from the pending list.
 *
 * <p><b>NOT an authority.</b> This carries NO authorizing columns — no owner, no domain, no
 * license, no role. A node self-claim is trivially spoofable from userspace; the trust gate is
 * headscale (it mints the keys) and authorization lives entirely in {@code device_registry} +
 * {@code device_ssh_license}, assigned by a SUPERADMIN. {@code reportCount} is incremented on
 * re-report so a runaway counter is an investigable DoS signal (the mTLS principal breadth is a
 * known residual).
 */
public record DeviceEnrollment(
        String id,
        String machineKeyFp,
        String hostname,
        String meshId,
        String tailnetId,
        Instant firstReportedAt,
        Instant lastReportedAt,
        long reportCount) {
}
