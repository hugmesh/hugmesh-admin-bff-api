package systems.hugmesh.adminbff.web.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;

/**
 * Body for {@code POST /bff/admin/forum/users/{id}/groups} — assign the user's phpBB
 * group. The closed vocabulary matches the three forum-managed phpBB built-in groups
 * the role→group mapping uses ({@code ADMINISTRATORS} ← ROLE_ADMIN,
 * {@code GLOBAL_MODERATORS} ← ROLE_MOD ∩ ROLE_FORUM, {@code REGISTERED} ← forum role).
 * forum-bff + the phpBB extension re-derive the authoritative set from the verified
 * JWT; this is the admin's explicit override request.
 */
public record ForumGroupRequest(
        @NotBlank(message = "group is required")
        @Pattern(regexp = "ADMINISTRATORS|GLOBAL_MODERATORS|REGISTERED",
                 message = "group must be one of ADMINISTRATORS, GLOBAL_MODERATORS, REGISTERED")
        String group) {
}
