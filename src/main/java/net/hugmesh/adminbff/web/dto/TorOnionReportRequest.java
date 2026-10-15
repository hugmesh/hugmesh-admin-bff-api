package net.hugmesh.adminbff.web.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import org.jspecify.annotations.Nullable;

import java.util.Map;

/**
 * Body for {@code POST /bff/internal/tor/onions} — a tor-selected node reporting the onion
 * hostnames it exports (hugmesh-admin-bff-api#108). Sent over the same channel and identity
 * as the device-enrollment self-report ({@code /bff/internal/**}, the in-cluster SERVICE
 * credential on top of mTLS). Telemetry only: nothing in it confers access.
 *
 * <ul>
 *   <li>{@code machineKeyFp} — the reporting node's {@code machine_key_fp} (required).</li>
 *   <li>{@code primary} — the content of {@code /var/lib/hugmesh/tor/hostname}, trimmed;
 *       omitted or {@code null} before tor has minted it.</li>
 *   <li>{@code domains} — {@code slug -> onion}, one entry per
 *       {@code /var/lib/hugmesh/tor/<slug>.hostname}; omitted or empty when there are none.
 *       A report REPLACES the node's previous one, so a withdrawn slug disappears.</li>
 * </ul>
 * The value rules (v3 onion, node slug, at most 64 domains) are checked by
 * {@code TorNodeService#report}; a violation is a 422.
 */
public record TorOnionReportRequest(
        @NotBlank(message = "machineKeyFp is required")
        @Size(max = 128, message = "machineKeyFp is too long")
        String machineKeyFp,

        @Size(max = 62, message = "primary is too long")
        @Nullable
        String primary,

        @Size(max = 64, message = "too many domain onions")
        @Nullable
        Map<String, String> domains) {
}
