package systems.hugmesh.adminbff.web.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.Size;

/**
 * Body for {@code POST/DELETE /bff/admin/allowlist}. Both fields are OPTIONAL — the
 * admin may invite/revoke an email, a discord handle, or both in one call — so
 * neither is {@code @NotBlank}; the controller treats a blank value as absent (its
 * existing semantics). The constraints only bound a PRESENT value so a malformed /
 * oversized email or handle is a clean 400 before any durable write or Casdoor call.
 *
 * <p>{@code email} is bounded to the {@code allowlist.handle} varchar(320) width;
 * {@code discord} to a sane handle length.
 */
public record AllowlistRequest(
        @Email(message = "email is not a valid address")
        @Size(max = 320, message = "email is too long")
        String email,

        @Size(max = 64, message = "discord handle is too long")
        String discord) {
}
