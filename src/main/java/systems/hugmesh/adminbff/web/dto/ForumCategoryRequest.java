package systems.hugmesh.adminbff.web.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import org.jspecify.annotations.Nullable;

/**
 * Body for {@code POST /bff/admin/forum/categories} — create a phpBB forum (category).
 * The forum-bff {@code ForumAdminController} → phpBB extension runs phpBB's own
 * {@code acp_forums} logic server-side; this is the minimal create payload.
 */
public record ForumCategoryRequest(
        @NotBlank(message = "name is required")
        @Size(max = 255, message = "name is too long")
        String name,

        @Size(max = 4000, message = "description is too long")
        @Nullable
        String description,

        @Nullable
        Integer parentId) {
}
