package systems.hugmesh.adminbff.web.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import org.jspecify.annotations.Nullable;

/**
 * Body for {@code POST /bff/superadmin/service-store/{domain}/scaffold} (SUPERADMIN) — request an
 * example STARTER codebase (an archetype) for a brand/domain (schema 320). The {@code domain} is
 * taken from the PATH (the superadmin's explicit target), NEVER from this body.
 *
 * <ul>
 *   <li>{@code serviceKey} — REQUIRED; the service being scaffolded (same {@code @NotBlank}/
 *       {@code @Size(128)} guard as {@link ServiceDeploymentRequest}). Feeds the rendered
 *       {@code APP_SLUG}; for a Java-package archetype (spring-bff) the derived slug must be
 *       {@code ^[a-z0-9]+$} — the service rejects a hyphenated/empty slug with a clear 400.</li>
 *   <li>{@code displayName} — nullable human label (defaults to {@code serviceKey} when rendering).</li>
 *   <li>{@code archetype} — REQUIRED; the catalog archetype id ({@code ^[a-z0-9-]{1,64}$}),
 *       additionally validated against the embedded {@code ScaffoldCatalog} in the service.</li>
 *   <li>{@code mountAt} — nullable federation mount hint ({@code ^/[A-Za-z0-9/_-]*$}).</li>
 *   <li>{@code requiresRole} — nullable {@code requiresRole} federation hint.</li>
 * </ul>
 */
public record ScaffoldServiceRequest(
        @NotBlank(message = "serviceKey is required")
        @Size(max = 128, message = "serviceKey is too long")
        String serviceKey,

        @Size(max = 128, message = "displayName is too long")
        @Nullable
        String displayName,

        @NotBlank(message = "archetype is required")
        @Pattern(regexp = "^[a-z0-9-]{1,64}$", message = "archetype must match ^[a-z0-9-]{1,64}$")
        String archetype,

        @Size(max = 128, message = "mountAt is too long")
        @Pattern(regexp = "^/[A-Za-z0-9/_-]*$", message = "mountAt must match ^/[A-Za-z0-9/_-]*$")
        @Nullable
        String mountAt,

        @Size(max = 32, message = "requiresRole is too long")
        @Nullable
        String requiresRole) {
}
