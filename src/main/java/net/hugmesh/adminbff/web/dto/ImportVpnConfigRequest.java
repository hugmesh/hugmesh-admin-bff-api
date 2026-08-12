package net.hugmesh.adminbff.web.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

/**
 * Body for {@code POST /bff/admin/egress-vpn/configs} (SUPERADMIN) — import a
 * provider-downloaded VPN config for the egress-VPN optional service.
 *
 * <ul>
 *   <li>{@code domain} — the owning brand/tenant (FIX-NODEFAULT: a real residency brand,
 *       not 'default'). The service rejects an unknown/'default' domain with a 422.</li>
 *   <li>{@code name} — the operator-facing config name (unique per active (domain,name)).</li>
 *   <li>{@code provider} — optional free-text provider label (e.g. "protonvpn").</li>
 *   <li>{@code config} — the raw WireGuard {@code .conf} (first-class) / OpenVPN
 *       {@code .ovpn} (fallback) text. PARSED + VALIDATED, then the kind + display
 *       endpoint are extracted — the body itself (incl. the private key) is NEVER
 *       persisted in the database; only the {@code secretRef} is stored.</li>
 *   <li>{@code secretRef} — optional name of the ESO-materialised K8s Secret carrying the
 *       config bytes (the runtime delivery path). Defaults server-side when absent.</li>
 * </ul>
 */
public record ImportVpnConfigRequest(
        @NotBlank(message = "domain is required")
        @Size(max = 64, message = "domain is too long")
        String domain,

        @NotBlank(message = "name is required")
        @Size(max = 128, message = "name is too long")
        String name,

        @Size(max = 64, message = "provider is too long")
        String provider,

        @NotBlank(message = "config is required (the WireGuard .conf / OpenVPN .ovpn text)")
        @Size(max = 65536, message = "config is too large")
        String config,

        @Size(max = 256, message = "secretRef is too long")
        String secretRef) {
}
