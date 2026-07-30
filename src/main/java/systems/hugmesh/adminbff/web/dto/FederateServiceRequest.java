package systems.hugmesh.adminbff.web.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import org.jspecify.annotations.Nullable;

/**
 * Body for {@code POST /bff/superadmin/service-store/{domain}/deployments/{id}/federate}
 * (SUPERADMIN) — register the deployment's UI as a federation module (an upsert-by-slug against
 * the federation-api admin API). The {@code domain} + deployment {@code id} come from the PATH.
 *
 * <ul>
 *   <li>{@code slug} — REQUIRED federation module slug ({@code ^[a-z0-9-]{1,64}$}).</li>
 *   <li>{@code mountAt} — REQUIRED mount path ({@code ^/[A-Za-z0-9/_-]*$}); carried into the
 *       module {@code metadata.mountAt}.</li>
 *   <li>{@code exposedModule} — REQUIRED exposed module (e.g. {@code ./routes}).</li>
 *   <li>{@code remoteEntryUrl} — REQUIRED remote-entry URL; {@code @Size(512)} here and
 *       structurally validated like a {@code repoUrl} (scheme/host/SSRF guard) in the service.</li>
 *   <li>{@code kind} — nullable module kind ({@code remote-shell}/{@code fragment}); the service
 *       defaults it to {@code remote-shell}.</li>
 *   <li>{@code visibility} — nullable ({@code public}/{@code internal}); the service defaults it
 *       to {@code internal}.</li>
 *   <li>{@code requiresRole} — nullable {@code requiresRole} carried into {@code metadata}.</li>
 * </ul>
 */
public record FederateServiceRequest(
        @NotBlank(message = "slug is required")
        @Pattern(regexp = "^[a-z0-9-]{1,64}$", message = "slug must match ^[a-z0-9-]{1,64}$")
        String slug,

        @NotBlank(message = "mountAt is required")
        @Size(max = 128, message = "mountAt is too long")
        @Pattern(regexp = "^/[A-Za-z0-9/_-]*$", message = "mountAt must match ^/[A-Za-z0-9/_-]*$")
        String mountAt,

        @NotBlank(message = "exposedModule is required")
        @Size(max = 128, message = "exposedModule is too long")
        String exposedModule,

        @NotBlank(message = "remoteEntryUrl is required")
        @Size(max = 512, message = "remoteEntryUrl is too long")
        String remoteEntryUrl,

        @Size(max = 32, message = "kind is too long")
        @Nullable
        String kind,

        @Size(max = 16, message = "visibility is too long")
        @Nullable
        String visibility,

        @Size(max = 32, message = "requiresRole is too long")
        @Nullable
        String requiresRole) {
}
