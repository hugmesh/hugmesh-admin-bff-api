package systems.hugmesh.adminbff.web.dto;

import io.swagger.v3.oas.annotations.media.Schema;

/**
 * The response of the ADMIN desktop step-up mint ({@code POST /bff/admin/desktop/step-up}). Carries
 * the opaque, single-use, short-TTL step-up token the UI then presents back on the device-terminal
 * WS handshake (subprotocol {@code hugmesh.device-terminal.stepup.<token>} for a browser, or the
 * {@code X-Device-Terminal-StepUp} header for a CLI) and on the remote-install POST (the SAME
 * header). A record so springdoc surfaces it typed in {@code /v3/api-docs} (a future ng-openapi-gen
 * adoption stays unblocked).
 *
 * @param stepUpToken the opaque token (per-subject, single-use, leader-pinned, constant-time
 *                    validated) — NEVER logged/persisted beyond the in-memory broker
 * @param ttlMinutes  the token's time-to-live in minutes (the WorkloadStepUpService TTL)
 */
@Schema(name = "DesktopTerminalStepUpResponse",
        description = "The minted desktop step-up token + its TTL (for the SSH-terminal handshake "
                + "and the remote-install header).")
public record DesktopTerminalStepUpResponse(
        @Schema(description = "Opaque single-use step-up token; present on the X-Device-Terminal-StepUp "
                + "header (CLI) or the hugmesh.device-terminal.stepup.<token> subprotocol (browser).")
        String stepUpToken,
        @Schema(description = "Token time-to-live in minutes.", example = "5")
        long ttlMinutes) {
}
