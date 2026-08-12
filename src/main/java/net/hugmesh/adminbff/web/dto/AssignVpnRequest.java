package net.hugmesh.adminbff.web.dto;

import jakarta.validation.constraints.Size;

/**
 * Body for the two assign endpoints (SUPERADMIN):
 * {@code POST /bff/admin/egress-vpn/configs/{configId}/assign/node/{nodeFp}} (DEVICE
 * scope — {@code nodeFp} = the node's {@code device_registry.machine_key_fp}) and
 * {@code POST /bff/admin/egress-vpn/configs/{configId}/assign/domain/{domain}} (DOMAIN
 * scope). The config + target are PATH variables; this body carries only the optional
 * per-service narrowing.
 *
 * <ul>
 *   <li>{@code serviceSlug} — optional per-service opt-in ({@code akkoma}/{@code tuwunel}/
 *       {@code coturn}); blank/absent = ALL public services in the target egress via the
 *       VPN.</li>
 * </ul>
 */
public record AssignVpnRequest(
        @Size(max = 64, message = "serviceSlug is too long")
        String serviceSlug) {

    /** A no-arg-equivalent convenience for an "all services" assignment. */
    public static AssignVpnRequest allServices() {
        return new AssignVpnRequest(null);
    }
}
