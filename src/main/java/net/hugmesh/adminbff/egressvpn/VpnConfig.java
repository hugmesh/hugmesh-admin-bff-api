package net.hugmesh.adminbff.egressvpn;

import java.time.Instant;

/**
 * A single {@code vpn_config} row — one imported provider VPN config for the DEFAULT-OFF
 * egress-VPN optional service (schema in Liquibase {@code db/changelog/080-egress-vpn-
 * configs.xml}). It is what an admin/superadmin imports (a ProtonVPN WireGuard {@code
 * .conf}, first-class, or an OpenVPN {@code .ovpn}, fallback) so mesh NODES can use it for
 * OUTGOING / egress traffic on PUBLIC-facing flows. CLONES the {@code device_ssh_license}
 * idioms.
 *
 * <p><b>secret_ref, NOT the secret.</b> This row holds ONLY a {@code secretRef} (the name
 * of the ESO-materialised K8s Secret carrying the actual config) + metadata. The {@code
 * .conf}/{@code .ovpn} bytes — and the private VPN key — NEVER land in this database
 * (secrets off-git / off-DB).
 *
 * <ul>
 *   <li>{@code domain} — the owning brand/tenant. NOT NULL, NO default [FIX-NODEFAULT];
 *       the service rejects {@code 'default'}. A scoped ADMIN reads only their brand's
 *       configs.</li>
 *   <li>{@code kind} — {@code wireguard} (first-class) / {@code openvpn} (fallback),
 *       CHECK-constrained.</li>
 *   <li>{@code endpoint} — the remote host:port parsed from the config for DISPLAY only.</li>
 *   <li>{@code state} — {@code active} / {@code revoked} (CAS, never deleted = audit).</li>
 *   <li>{@code propagationState} — the push-with-ack outcome the UI surfaces.</li>
 *   <li>{@code generation} — monotonic, bumped on every mutate; the signed export's
 *       rollback guard reads {@code max(generation)}.</li>
 * </ul>
 */
public record VpnConfig(
        String id,
        String domain,
        String name,
        String kind,
        String provider,
        String endpoint,
        String secretRef,
        String state,
        String createdBy,
        Instant createdAt,
        Instant revokedAt,
        String revokedBy,
        String propagationState,
        long generation) {

    public static final String KIND_WIREGUARD = "wireguard";
    public static final String KIND_OPENVPN = "openvpn";

    public static final String STATE_ACTIVE = "active";
    public static final String STATE_REVOKED = "revoked";

    public static final String PROP_PENDING = "pending";
    public static final String PROP_APPLIED = "applied";
    public static final String PROP_FAILED = "failed";
    public static final String PROP_DEGRADED = "degraded";

    public boolean isActive() {
        return STATE_ACTIVE.equals(state);
    }
}
