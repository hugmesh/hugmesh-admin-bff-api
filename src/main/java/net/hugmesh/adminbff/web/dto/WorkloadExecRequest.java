package net.hugmesh.adminbff.web.dto;

import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.Size;

import java.util.List;

/**
 * Body for {@code POST /bff/superadmin/workloads/exec/{namespace}/{pod}} (SUPERADMIN,
 * DANGEROUS) — the one-shot READ-ONLY exec variant (DECISION 1). The {@code command} is an
 * argv (one list element per argument, never a shell string) and the WHOLE argv must equal one
 * entry of the server-side read-only allowlist, token for token — {@code ["ps","-e"]} matches
 * the entry {@code "ps -e"}, {@code ["ps -e"]} and {@code ["ps","-e","eww"]} do not (see
 * {@code WorkloadConsoleProperties#execReadOnlyAllowed}); the full interactive TTY exec is the
 * WebSocket path, not this endpoint.
 */
public record WorkloadExecRequest(
        @Size(max = 253, message = "container is too long")
        String container,

        @NotEmpty(message = "command is required")
        @Size(max = 32, message = "command has too many tokens")
        List<String> command) {
}
