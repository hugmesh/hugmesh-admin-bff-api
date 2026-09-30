package net.hugmesh.adminbff.web.dto;

import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.Size;

import java.util.List;

/**
 * Body for {@code POST /bff/superadmin/workloads/exec/{namespace}/{pod}} (SUPERADMIN,
 * DANGEROUS) — the one-shot READ-ONLY exec variant (DECISION 1). The {@code command} is an
 * argv (one list element per argument, never a shell string). It must be licensed by the
 * server-side read-only allowlist: a BARE-NAME entry ({@code "ls"}) licenses that command with
 * any arguments, a PINNED-ARGV entry ({@code "ps -e"}) licenses exactly that whole argv, so
 * {@code ["ps","-e"]} matches but {@code ["ps -e"]} and {@code ["ps","-e","eww"]} do not (see
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
