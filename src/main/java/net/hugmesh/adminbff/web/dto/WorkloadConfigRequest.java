package net.hugmesh.adminbff.web.dto;

/**
 * Body for {@code PUT /bff/superadmin/workloads/config/{domain}} (SUPERADMIN) — flip the
 * WORKLOAD CONSOLE master kill-switch for a domain (or the GLOBAL sentinel). Both flags
 * default DARK and must be deliberately enabled:
 * <ul>
 *   <li>{@code adminEnabled} — whether a granted admin sees anything (DECISION 4);</li>
 *   <li>{@code dangerousTierEnabled} — the GLOBAL kill of exec/log-stream/mutations that
 *       applies EVEN to a superadmin (DECISION 5); set on the GLOBAL row.</li>
 * </ul>
 */
public record WorkloadConfigRequest(
        boolean adminEnabled,
        boolean dangerousTierEnabled) {
}
