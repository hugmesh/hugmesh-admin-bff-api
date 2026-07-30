package systems.hugmesh.adminbff.web.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Positive;
import jakarta.validation.constraints.Size;
import org.jspecify.annotations.Nullable;

/**
 * Body for {@code POST /bff/games-services/instances} (ROLE_GAMES_SERVICES_ADMIN) — request
 * a new per-domain game-server instance (schema 091). The domain + owner come from the
 * validated JWT (NOT the body): domain from the issuer, owner from the subject.
 *
 * <ul>
 *   <li>{@code slug} — the catalog server to run; must be offered + enabled for the caller's
 *       domain (the creation gate, enforced in
 *       {@link systems.hugmesh.adminbff.gamesservices.GameInstanceService}).</li>
 *   <li>{@code name} — a DNS-label instance name unique within (domain, slug).</li>
 *   <li>{@code ttlSeconds} — optional auto-terminate TTL; {@code null} = runs until
 *       explicitly stopped. Drives the {@code ending_at} single expiry clock.</li>
 * </ul>
 */
public record CreateGameInstanceRequest(
        @NotBlank(message = "slug is required")
        @Size(max = 64, message = "slug is too long")
        String slug,

        @NotBlank(message = "name is required")
        @Size(max = 64, message = "name is too long")
        String name,

        @Positive(message = "ttlSeconds must be positive")
        @Nullable
        Long ttlSeconds) {
}
