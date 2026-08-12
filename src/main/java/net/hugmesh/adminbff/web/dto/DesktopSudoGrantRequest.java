package net.hugmesh.adminbff.web.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

/**
 * Body for {@code POST /bff/admin/desktop/sudo/grant} (ADMIN/SUPERADMIN) — grant a desktop
 * user SSO-enforced sudo on a device. The grant's {@code domain} is stamped from the
 * device's residency (never the body), so this carries only the subject + target device.
 *
 * <ul>
 *   <li>{@code subject} — the Casdoor subject being granted sudo.</li>
 *   <li>{@code deviceId} — the {@code device_registry} id of the desktop device.</li>
 * </ul>
 */
public record DesktopSudoGrantRequest(
        @NotBlank(message = "subject is required")
        @Size(max = 400, message = "subject is too long")
        String subject,

        @NotBlank(message = "deviceId is required")
        @Size(max = 36, message = "deviceId is too long")
        String deviceId) {
}
