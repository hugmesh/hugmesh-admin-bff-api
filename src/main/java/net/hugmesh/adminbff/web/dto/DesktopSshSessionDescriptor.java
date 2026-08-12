package net.hugmesh.adminbff.web.dto;

import io.swagger.v3.oas.annotations.media.Schema;

/**
 * The pre-WS SESSION DESCRIPTOR returned by {@code POST /bff/admin/desktop/ssh-terminal/sessions} —
 * the SINGLE place the UI learns the REAL live device-terminal WebSocket coordinates. It carries the
 * exact {@code wsPath} the live {@code DeviceSshTerminalWebSocketHandler} is mounted at
 * ({@code /bff/admin/device-terminal/{deviceId}}), whether the live transport ships dark, and that a
 * step-up token is required on the handshake — eliminating the UI's previously-hardcoded wrong path.
 *
 * <p>NON-SECRET: carries NO token (the UI mints one separately via {@code /bff/admin/desktop/step-up}).
 * It is only returned to a caller who has just passed the same own-domain device-ssh-license
 * authorization the socket itself re-verifies; the WS handler NEVER trusts this REST call and
 * re-runs all five connect-time gates regardless. A record so springdoc surfaces it typed.
 *
 * @param deviceId       the authorized target device id
 * @param dark           true while {@code app.device-terminal.enabled=false} (the live WS opens no
 *                       real transport — the UI shows the greyed/dark pane)
 * @param wsPath         the REAL live WS handshake path (matches the handler's ROUTE_SEGMENT)
 * @param stepUpRequired always true — the handshake must carry a valid step-up token
 * @param note           a human-readable note for the UI
 */
@Schema(name = "DesktopSshSessionDescriptor",
        description = "Pre-WS descriptor: the real device-terminal WebSocket path + dark flag + "
                + "step-up requirement (the UI's source of the live coordinates).")
public record DesktopSshSessionDescriptor(
        @Schema(description = "The authorized target device id.") String deviceId,
        @Schema(description = "True while the live transport ships dark (app.device-terminal.enabled=false).")
        boolean dark,
        @Schema(description = "The real live WS handshake path (/bff/admin/device-terminal/{deviceId}).")
        String wsPath,
        @Schema(description = "Whether the WS handshake requires a step-up token (always true).")
        boolean stepUpRequired,
        @Schema(description = "Human-readable note for the UI.") String note) {
}
