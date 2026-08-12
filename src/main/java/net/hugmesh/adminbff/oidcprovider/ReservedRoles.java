package net.hugmesh.adminbff.oidcprovider;

import java.util.Locale;
import java.util.Set;

/**
 * The reserved / bootstrap-role DENYLIST shared by the OIDC default-role WRITE path
 * ({@link OidcProviderRolesController#setProviderRoles}) and the first-login APPLY path
 * ({@link OidcFirstLoginController#firstLogin}).
 *
 * <p><b>Why this exists.</b> The OIDC default-role map is an indirect role-grant channel:
 * an ADMIN configures the roles a brand-new OIDC user auto-receives, and the first-login
 * hook later applies them verbatim via {@code CasdoorAdminClient.addUserToRole}. That is
 * the SAME privilege boundary {@code AdminController.grantRole} deliberately enforces with
 * its {@code GRANTABLE_ROLE_PATTERN} — whose comment states that the service / bootstrap
 * roles ({@code ROLE_SUPERADMIN}, {@code ROLE_GATEWAY}, {@code ROLE_API},
 * {@code ROLE_ADMIN_API}, {@code ROLE_SERVICE}) are NOT grantable and "can only be assigned
 * via the generator / Casdoor init_data seed". Without this guard a brand ADMIN could set a
 * provider's default roles to include {@code superadmin} (a cross-tenant super-role) or a
 * service role, escalating themselves (or a confederate) past the {@code grantRole} control.
 *
 * <p><b>Denylist, not allowlist — and why.</b> Unlike {@code grantRole}'s closed allowlist,
 * the OIDC default-role feature is an extensible capability/service-role channel (the stored
 * names are free-form {@code [a-z0-9_-]+} short names, e.g. a future {@code tube} or
 * {@code owncast} capability role). A strict allowlist would break legitimate, not-yet-listed
 * capability roles. So we instead block PRECISELY the reserved escalation set and leave the
 * capability set open. Plain {@code admin} is deliberately ALLOWED as a default (it IS in
 * {@code GRANTABLE_ROLE_PATTERN}); only {@code superadmin} and the service/bootstrap roles
 * are denied.
 *
 * <p><b>Normalisation.</b> Stored names are matched in the same canonical form
 * {@link OidcFirstLoginController#casdoorRoleName} produces — trimmed, upper-cased, with any
 * hyphen folded to an underscore — so {@code admin-api} and {@code admin_api} both resolve to
 * the reserved {@code ADMIN_API} token. The check is fail-closed: a null/blank token is
 * treated as reserved (rejected) since it can never be a legitimate role.
 */
final class ReservedRoles {

    private ReservedRoles() {
    }

    /**
     * Reserved / bootstrap roles that may NEVER be set as an OIDC default role.
     * Canonical form: upper-cased, hyphen→underscore, {@code ROLE_} prefix stripped — i.e.
     * the suffix of the {@code ROLE_SUPERADMIN}/{@code ROLE_GATEWAY}/{@code ROLE_API}/
     * {@code ROLE_ADMIN_API}/{@code ROLE_SERVICE} names {@code grantRole} forbids.
     */
    private static final Set<String> RESERVED = Set.of(
            "SUPERADMIN", "GATEWAY", "API", "ADMIN_API", "SERVICE");

    /**
     * The canonical reserved-token form of a stored short-name: trimmed, upper-cased, with
     * hyphens folded to underscores (mirrors {@code OidcFirstLoginController.casdoorRoleName}
     * minus the {@code ROLE_} prefix). Returns {@code ""} for a null/blank input.
     */
    private static String canonical(String stored) {
        if (stored == null) {
            return "";
        }
        return stored.trim().toUpperCase(Locale.ROOT).replace('-', '_');
    }

    /**
     * {@code true} iff {@code stored} is a reserved / bootstrap role that must never be
     * granted via the OIDC default-role channel. Fail-closed: a null/blank token is reserved.
     *
     * @param stored the lowercase stored short-name (e.g. {@code "superadmin"}, {@code "admin-api"})
     * @return {@code true} if the role is reserved and must be rejected
     */
    static boolean isReserved(String stored) {
        String token = canonical(stored);
        return token.isEmpty() || RESERVED.contains(token);
    }
}
