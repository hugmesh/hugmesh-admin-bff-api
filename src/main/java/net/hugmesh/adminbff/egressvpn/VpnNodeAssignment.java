package net.hugmesh.adminbff.egressvpn;

import java.time.Instant;

/**
 * A single {@code vpn_node_assignment} row — the explicit (config x NODE|DOMAIN)
 * assignment that marks which public pods egress via the VPN (schema in Liquibase
 * {@code db/changelog/080-egress-vpn-configs.xml}). DUAL SCOPE, CLONING the
 * {@code device_ssh_license} (operator x device|domain) idiom:
 *
 * <ul>
 *   <li>{@code scopeType} — {@code DEVICE} (one node, {@code targetNodeId} = the node's
 *       {@code device_registry.machine_key_fp}) or {@code DOMAIN} (all public pods in
 *       {@code targetDomain}). The {@code chk_vpn_scope_shape} XOR ties exactly one target
 *       to the shape.</li>
 *   <li>{@code serviceSlug} — optional per-service opt-in ({@code akkoma}/{@code tuwunel}/
 *       {@code coturn}); {@code null} = ALL public services in the target egress via the
 *       VPN. (v1 keeps akkoma/tuwunel HTTP on the existing Squid egress-proxy; the VPN is
 *       primarily for coturn UDP + made-public egress, and akkoma/tuwunel is loosened onto
 *       the VPN only on an explicit assignment.)</li>
 *   <li>{@code state} — {@code active} / {@code revoked} (CAS, never deleted = audit).</li>
 *   <li>{@code domain} — home/tenant discriminator for the ADMIN read view, stamped from
 *       the config's residency [FIX-NODEFAULT], never the caller.</li>
 *   <li>{@code generation} / {@code propagationState} — mirror {@link VpnConfig}.</li>
 * </ul>
 */
public record VpnNodeAssignment(
        String id,
        String configId,
        String scopeType,
        String targetNodeId,
        String targetDomain,
        String serviceSlug,
        String state,
        String assignedBy,
        Instant assignedAt,
        Instant revokedAt,
        String revokedBy,
        String domain,
        String propagationState,
        long generation) {

    public static final String SCOPE_DEVICE = "DEVICE";
    public static final String SCOPE_DOMAIN = "DOMAIN";

    public static final String STATE_ACTIVE = "active";
    public static final String STATE_REVOKED = "revoked";

    public static final String PROP_PENDING = "pending";

    public boolean isActive() {
        return STATE_ACTIVE.equals(state);
    }

    public boolean isDeviceScoped() {
        return SCOPE_DEVICE.equals(scopeType);
    }

    public boolean isDomainScoped() {
        return SCOPE_DOMAIN.equals(scopeType);
    }
}
