package net.hugmesh.adminbff.web.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import org.jspecify.annotations.Nullable;

/**
 * Body for {@code POST /bff/superadmin/app-profiles} (create) and
 * {@code PUT /bff/superadmin/app-profiles/{name}} (update) — a reusable, SUPERADMIN-owned
 * deploy template (schema 101).
 *
 * <ul>
 *   <li>{@code name} — the UNIQUE natural key (required on create; ignored on update, where
 *       the path {@code {name}} identifies the row). Validated non-blank + bounded so a
 *       malformed create is a clean 400; a duplicate is a clean 409 from the service.</li>
 *   <li>{@code profileJson} — opaque resource/role/cert/exposure DEFAULTS as a JSON
 *       document string. Bounded but otherwise unparsed in PR1 (the later effector resolves
 *       it).</li>
 * </ul>
 */
public record AppProfileRequest(
        @NotBlank(message = "name is required")
        @Size(max = 128, message = "name is too long")
        String name,

        @Size(max = 1_000_000, message = "profileJson is too long")
        @Nullable
        String profileJson) {
}
