package net.hugmesh.adminbff.web.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

/**
 * Body for {@code POST /bff/admin/forum/styles} and
 * {@code POST /bff/admin/forum/extensions} — install a phpBB style or extension.
 * ADMIN-ONLY (full ACP {@code acp_styles}/{@code acp_extensions} parity). Since our
 * Angular forum-ui is the single source of truth and NO phpBB CSS reaches the browser,
 * an installed style affects only phpBB-internal rendering; the capability stays
 * admin-gated for ACP parity.
 */
public record ForumInstallRequest(
        @NotBlank(message = "name is required")
        @Size(max = 255, message = "name is too long")
        String name) {
}
