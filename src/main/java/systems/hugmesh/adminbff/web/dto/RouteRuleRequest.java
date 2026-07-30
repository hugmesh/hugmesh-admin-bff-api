package systems.hugmesh.adminbff.web.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

/**
 * Body for {@code POST /bff/admin/route-access} (add a per-gateway role→URL access
 * rule). {@code gateway} + {@code url_pattern} + {@code role} are required and
 * length-bounded to their {@code gateway_route_access} column widths; the
 * addressable-first-segment + reserved-prefix-warning logic stays in the controller
 * (it returns the contract's specific error/warning shape). {@code allow} defaults
 * true at the controller. The non-blank requirement mirrors the DB
 * {@code ck_gra_nonblank} CHECK (changeset 007).
 *
 * <p>JSON field names match the existing untyped contract exactly (incl. the
 * snake_case {@code url_pattern} / {@code casdoor_user} / {@code mfa_required}).
 *
 * <p>{@code mfaRequired} (the dual-write trio's per-row MFA flag) is OPTIONAL and defaults
 * false at the controller (null -> false), so an existing add request that omits it lands a
 * row with mfa_required=false — byte-identical to today. admin-bff persists the column for
 * consistency with the gateway/generator; it does NOT enforce MFA (the gateway does).
 */
public record RouteRuleRequest(
        @NotBlank(message = "gateway is required")
        @Size(max = 255, message = "gateway is too long")
        String gateway,

        @com.fasterxml.jackson.annotation.JsonProperty("url_pattern")
        @NotBlank(message = "url_pattern is required")
        @Size(max = 512, message = "url_pattern is too long")
        @Pattern(regexp = "/.*", message = "url_pattern must start with '/'")
        String urlPattern,

        @NotBlank(message = "role is required")
        @Size(max = 255, message = "role is too long")
        String role,

        @com.fasterxml.jackson.annotation.JsonProperty("casdoor_user")
        @Size(max = 255, message = "casdoor_user is too long")
        String casdoorUser,

        Boolean allow,

        @com.fasterxml.jackson.annotation.JsonProperty("mfa_required")
        Boolean mfaRequired) {
}
