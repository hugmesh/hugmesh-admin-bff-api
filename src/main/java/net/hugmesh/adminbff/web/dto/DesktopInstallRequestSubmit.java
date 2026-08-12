package net.hugmesh.adminbff.web.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

/**
 * Body for {@code POST /bff/desktop/install-requests} (any authenticated desktop user) —
 * ask an admin to allow/install an app on the user's device. The {@code requester} and
 * {@code domain} are NEVER body fields (they are the caller's validated JWT subject + issuer,
 * owner == subject); this carries only the app ref + the target device.
 */
public record DesktopInstallRequestSubmit(
        @NotBlank(message = "appRef is required")
        @Size(max = 512, message = "appRef is too long")
        String appRef,

        @NotBlank(message = "deviceId is required")
        @Size(max = 36, message = "deviceId is too long")
        String deviceId) {
}
