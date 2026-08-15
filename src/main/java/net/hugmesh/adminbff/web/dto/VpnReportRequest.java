package net.hugmesh.adminbff.web.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

/**
 * Body for {@code PUT /bff/admin/egress-vpn/report} — the node-level
 * {@code hugmesh-vpn-reconcile} agent reporting its per-node propagation outcome back so the
 * UI stops showing {@code pending} forever. Consumed over the SAME transport + identity as the
 * signed {@code /export} it follows (in-cluster mTLS SUPERADMIN); the fp names the reporting
 * node exactly as the export's {@code ?node=} does.
 *
 * <ul>
 *   <li>{@code node} — the reporting node's {@code device_registry.machine_key_fp}. An
 *       unknown fp transitions NOTHING (fail-closed, mirrors the export's empty body).</li>
 *   <li>{@code state} — the outcome: {@code applied} / {@code failed} / {@code degraded}
 *       (the agent's report_state vocabulary; {@code pending} is a MUTATION reset, never a
 *       report). Out-of-vocabulary is a 422.</li>
 * </ul>
 */
public record VpnReportRequest(
        @NotBlank(message = "node is required")
        @Size(max = 128, message = "node is too long")
        String node,

        @NotBlank(message = "state is required")
        @Size(max = 16, message = "state is too long")
        String state) {
}
