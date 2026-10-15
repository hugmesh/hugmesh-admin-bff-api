package net.hugmesh.adminbff.web.dto;

import jakarta.validation.constraints.Size;
import org.jspecify.annotations.Nullable;

/**
 * Body for {@code PUT /bff/admin/tor/nodes/{fp}/upstream} (SUPERADMIN): what the node's
 * {@code /etc/hugmesh/tor/upstream} must hold, delivered by the signed per-node Tor export
 * (hugmesh-admin-bff-api#108).
 *
 * <ul>
 *   <li>{@code upstream} — one {@code host:port} token (hostname, IPv4 or {@code [IPv6]}),
 *       validated against the node agent's own rule so the node never ignores it; or
 *       {@code null} for the agent's built-in default ({@code 127.0.0.1:443}, correct only
 *       on the ingress-edge node), in which case the agent removes the file.</li>
 * </ul>
 */
public record TorUpstreamRequest(
        @Size(max = 300, message = "upstream is too long")
        @Nullable
        String upstream) {
}
