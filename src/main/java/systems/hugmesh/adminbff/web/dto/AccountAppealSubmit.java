package systems.hugmesh.adminbff.web.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import org.springframework.lang.Nullable;

/**
 * Body for {@code POST /bff/me/appeal} — a curtailed principal's OWN structured appeal
 * against their {@code access_suspension} state. {@code userSub}/{@code handle}/
 * {@code domain} are NEVER body fields (they are the caller's own resolved account
 * identity, owner == subject); this carries only the appellant's message + an optional
 * alternate contact (the appellant may lose the ability to sign in again before the
 * appeal is reviewed).
 */
public record AccountAppealSubmit(
        @NotBlank(message = "reason is required")
        @Size(max = 2000, message = "reason is too long")
        String reason,

        @Nullable
        @Email(message = "contactEmail must be a valid email address")
        @Size(max = 320, message = "contactEmail is too long")
        String contactEmail) {
}
