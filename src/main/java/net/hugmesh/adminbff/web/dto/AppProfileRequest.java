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
 *   <li>{@code profileJson} — resource/role/cert/exposure DEFAULTS as a JSON document string.
 *       The WIRE shape is unchanged (still a bounded string, so the generated clients and this
 *       repo's {@code openapi.json} do not move), but since issue #55 the CONTENT is validated
 *       on save against the committed JSON Schema
 *       ({@link net.hugmesh.adminbff.servicecatalog.AppProfileSchema}, a byte-identical copy of
 *       the Service Catalog console's {@code schemas/app-profile.schema.json}). A body the
 *       console would refuse is a 400 here too, with every offending path named — so a direct
 *       API call or a stale browser tab cannot store one. The values are still not RESOLVED by
 *       anything; that is the effector, open on catalog-ui#3.</li>
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
