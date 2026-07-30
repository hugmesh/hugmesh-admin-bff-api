package systems.hugmesh.adminbff.routeaccess;

import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * A per-gateway external-access rule. JSON shape matches the verified contract
 * (mock-bff.mjs) and the Postgres gateway_route_access columns: which Casdoor
 * role (or a specific casdoor_user) may reach which URL pattern from outside a
 * given gateway. {@code allow=false} is an explicit deny.
 */
public record RouteRule(
        String id,
        String gateway,
        @JsonProperty("url_pattern") String urlPattern,
        String role,
        @JsonProperty("casdoor_user") String casdoorUser,
        boolean allow,
        /** Tenant/brand discriminator, derived from the validated token issuer and
         *  stamped on write. {@code "default"} on single-issuer clusters. A scoped
         *  admin only ever lists/deletes rules in their own brand; SUPERADMIN sees
         *  all. The Cassandra mirror the gateways poll does not carry this column
         *  (each gateway derives its own domain from its issuer). */
        String domain,
        /** Per-row MFA REQUIREMENT — the 8th field of the dual-write trio, matching the
         *  gateway {@code GatewayRouteAccessService.Rule} mfaRequired field + the generator
         *  {@code 20-schema.sql} `mfa_required boolean NOT NULL DEFAULT false`. DEFAULT false:
         *  admin-bff reads/writes it through but does NOT enforce MFA (the gateway's
         *  GatewayRouteAccessFilter.decide() is the sole enforcer). */
        @JsonProperty("mfa_required") boolean mfaRequired) {

    /** Back-compat 7-arg constructor (pre-trio callers): mfaRequired defaults false, so
     *  every existing add/list site is byte-identical (the DB column also defaults false). */
    public RouteRule(String id, String gateway, String urlPattern, String role,
                     String casdoorUser, boolean allow, String domain) {
        this(id, gateway, urlPattern, role, casdoorUser, allow, domain, false);
    }
}
