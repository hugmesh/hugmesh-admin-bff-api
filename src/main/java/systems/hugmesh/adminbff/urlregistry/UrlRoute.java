package systems.hugmesh.adminbff.urlregistry;

import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * A DB-driven gateway ROUTE DEFINITION (distinct from a route-ACCESS rule). JSON
 * shape + Cassandra columns match hugmesh_gateway.url_registry (see
 * hugmesh-gateway {@code UrlRegistryService}): which {@code pathPrefix} maps
 * to which {@code downstreamUri}, owned by {@code serviceName}, with an optional
 * {@code requiredRole} fine-grained auth override. {@code pathPrefix} is the
 * primary key — a POST with an existing prefix is an upsert.
 *
 * <p>{@code stripPrefix} mirrors the {@code strip_prefix int} column (gateway
 * migration 008): {@code null} or {@code <= 0} means "no StripPrefix filter", a
 * positive {@code N} makes the gateway emit a {@code StripPrefix=N} filter on the
 * route (reproducing a static YAML route's {@code - StripPrefix=N}). Nullable so a
 * row seeded before the column existed (or a route that does not strip) reads back
 * as {@code null}.
 */
public record UrlRoute(
        @JsonProperty("pathPrefix") String pathPrefix,
        @JsonProperty("downstreamUri") String downstreamUri,
        @JsonProperty("serviceName") String serviceName,
        @JsonProperty("requiredRole") String requiredRole,
        @JsonProperty("stripPrefix") Integer stripPrefix) {
}
