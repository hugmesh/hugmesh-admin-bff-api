package net.hugmesh.adminbff.web.dto;

import jakarta.validation.constraints.NotNull;

/**
 * Body for {@code PUT /bff/admin/announcements/suppression} — toggle the per-domain
 * {@code @system} BROADCAST kill-switch on or off. A single required boolean; the
 * acting principal's domain is derived from their validated JWT (never carried in the
 * body), so a scoped admin can only toggle their OWN brand's flag.
 */
public record AnnouncementSuppressionRequest(
        @NotNull(message = "suppressed is required")
        Boolean suppressed) {
}
