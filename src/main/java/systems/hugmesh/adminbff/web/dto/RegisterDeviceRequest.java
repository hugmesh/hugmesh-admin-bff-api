package systems.hugmesh.adminbff.web.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import org.jspecify.annotations.Nullable;

/**
 * Body for {@code POST /bff/admin/device-licenses/register} (SUPERADMIN) — registers one
 * mesh node in the device registry (schema 011). The {@code @NotBlank}/{@code @Pattern}
 * guards make a malformed registration a clean 400 (mapped by
 * {@link systems.hugmesh.adminbff.web.ValidationExceptionHandler}) BEFORE any write;
 * the FIX-NODEFAULT residency guard (multi-issuer required + domain != 'default') is
 * enforced in {@link systems.hugmesh.adminbff.device.DeviceRegistryService}.
 *
 * <ul>
 *   <li>{@code machineKeyFp} — the stable headscale machine-key fingerprint (UNIQUE
 *       identity).</li>
 *   <li>{@code hostname} — the node hostname.</li>
 *   <li>{@code imageType} — closed vocabulary matching the DB CHECK.</li>
 *   <li>{@code ownerType} — {@code SUPERADMIN} (primary/core) or {@code ADMIN}
 *       (mesh-extension), matching the DB CHECK.</li>
 *   <li>{@code physicalOwner} — the Casdoor subject who physically owns the device.</li>
 *   <li>{@code domain} — the residency brand. REQUIRED, NO default (FIX-NODEFAULT); the
 *       service rejects {@code 'default'}.</li>
 *   <li>{@code meshId} — the headscale mesh the node is enrolled in.</li>
 * </ul>
 */
public record RegisterDeviceRequest(
        @NotBlank(message = "machineKeyFp is required")
        @Size(max = 128, message = "machineKeyFp is too long")
        String machineKeyFp,

        @NotBlank(message = "hostname is required")
        @Size(max = 253, message = "hostname is too long")
        String hostname,

        @Size(max = 128, message = "tailnetId is too long")
        @Nullable
        String tailnetId,

        @Pattern(regexp = "primary|mesh-extension|client",
                 message = "imageType must be one of primary, mesh-extension, client")
        String imageType,

        @Size(max = 64, message = "hardwareClass is too long")
        @Nullable
        String hardwareClass,

        @Pattern(regexp = "SUPERADMIN|ADMIN",
                 message = "ownerType must be one of SUPERADMIN, ADMIN")
        String ownerType,

        @NotBlank(message = "physicalOwner is required")
        @Size(max = 400, message = "physicalOwner is too long")
        String physicalOwner,

        @NotBlank(message = "domain (residency) is required")
        @Size(max = 64, message = "domain is too long")
        String domain,

        @NotBlank(message = "meshId is required")
        @Size(max = 64, message = "meshId is too long")
        String meshId) {
}
