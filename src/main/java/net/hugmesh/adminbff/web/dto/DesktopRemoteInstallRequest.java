package net.hugmesh.adminbff.web.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

/**
 * Body for {@code POST /bff/admin/desktop/remote-install} (ADMIN/SUPERADMIN) — trigger a
 * one-click remote install of an app on a desktop device, riding the admin's device-SSH
 * license. The {@code operator} is NEVER a body field (it is the caller's validated JWT
 * subject — the ssh-license key); this carries only the target device + the app ref.
 */
public record DesktopRemoteInstallRequest(
        @NotBlank(message = "deviceId is required")
        @Size(max = 36, message = "deviceId is too long")
        String deviceId,

        @NotBlank(message = "appRef is required")
        @Size(max = 512, message = "appRef is too long")
        // SECURITY: appRef is spliced into a remote-shell install command
        // (RestDesktopSshClient → session.exec). Restrict to a Flatpak/OCI-ref
        // charset so no shell metacharacter/whitespace/newline can reach the SSH
        // command (defence-in-depth for the dark remote-install path).
        @Pattern(regexp = "^[A-Za-z0-9][A-Za-z0-9._+/:@-]*$",
                message = "appRef may contain only letters, digits and . _ + - / : @")
        String appRef) {
}
