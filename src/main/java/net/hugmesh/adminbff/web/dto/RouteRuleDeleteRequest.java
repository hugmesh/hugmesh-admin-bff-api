package net.hugmesh.adminbff.web.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;

/**
 * Body for {@code DELETE /bff/admin/route-access}: the rule {@code id} (a UUID). The
 * {@code @Pattern} guards the UUID shape so a malformed id is a clean 400 here
 * instead of the {@code RouteAccessRepository.delete}'s {@code UUID.fromString(id)}
 * throwing {@code IllegalArgumentException} (which would surface as a 500).
 */
public record RouteRuleDeleteRequest(
        @NotBlank(message = "id is required")
        @Pattern(regexp = "[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}",
                message = "id must be a UUID")
        String id) {
}
