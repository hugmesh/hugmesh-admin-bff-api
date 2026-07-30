package systems.hugmesh.adminbff.web.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.PositiveOrZero;
import jakarta.validation.constraints.Size;

/**
 * Body for {@code POST /bff/admin/routes} (upsert a gateway route DEFINITION in the
 * url_registry). {@code pathPrefix} + {@code downstreamUri} are required;
 * {@code serviceName} / {@code requiredRole} / {@code stripPrefix} are optional. The
 * addressable-first-segment + reserved-prefix-warning logic stays in the controller.
 * JSON field names match the existing contract exactly.
 *
 * <p>{@code stripPrefix} maps to the gateway's {@code strip_prefix int} column
 * (migration 008): omit it (or {@code 0}) for no strip, or a positive {@code N} to
 * make the gateway emit a {@code StripPrefix=N} filter. {@code @PositiveOrZero}
 * rejects a negative value; {@code null} (omitted) is allowed and means "no strip".
 */
public record UrlRouteRequest(
        @JsonProperty("pathPrefix")
        @NotBlank(message = "pathPrefix is required")
        @Size(max = 512, message = "pathPrefix is too long")
        @Pattern(regexp = "/.*", message = "pathPrefix must start with '/'")
        String pathPrefix,

        @JsonProperty("downstreamUri")
        @NotBlank(message = "downstreamUri is required")
        @Size(max = 1024, message = "downstreamUri is too long")
        String downstreamUri,

        @JsonProperty("serviceName")
        @Size(max = 255, message = "serviceName is too long")
        String serviceName,

        @JsonProperty("requiredRole")
        @Size(max = 255, message = "requiredRole is too long")
        String requiredRole,

        @JsonProperty("stripPrefix")
        @PositiveOrZero(message = "stripPrefix must be >= 0")
        Integer stripPrefix) {
}
