package systems.hugmesh.adminbff.web.dto;

import jakarta.validation.constraints.Size;
import org.jspecify.annotations.Nullable;

/**
 * Body for {@code POST /bff/admin/forum/users/{id}/ban} — the OPTIONAL ban reason.
 * The authoritative {@code id} is the PATH variable (validated there). The ban is
 * REVERSIBLE: {@code DELETE /bff/admin/forum/users/{id}/ban} lifts it. The whole body
 * is optional (a no-reason ban is allowed). Mirrors {@code SuspensionRequest}.
 */
public record ForumBanRequest(
        @Size(max = 1024, message = "reason is too long")
        @Nullable
        String reason) {
}
