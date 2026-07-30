package systems.hugmesh.adminbff.web.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;

/**
 * Body for {@code PUT /bff/superadmin/phone-devices/{deviceId}/management} (SUPERADMIN +
 * step-up) — set the AUTHORITATIVE managed/BYOD discriminator on a phone. {@code mode} is a
 * single word, so it carries NO {@code @JsonProperty} (this repo has no global naming
 * strategy; the multi-word ingest DTO annotates per field, a one-word field does not). The
 * closed vocabulary is pinned here (400 on anything else), re-checked in the service (422),
 * and backstopped by the DB CHECK.
 */
public record PhoneManagementModeRequest(
        @NotBlank(message = "mode is required")
        @Pattern(regexp = "unmanaged|mesh_owned",
                 message = "mode must be 'unmanaged' or 'mesh_owned'")
        String mode) {
}
