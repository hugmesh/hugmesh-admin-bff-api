package net.hugmesh.adminbff.capability;

import java.time.Instant;

/**
 * A DOMAIN CAPABILITY GATE row — two independent boolean keys per (domain, capability)
 * pair, plus a GLOBAL {@link #GLOBAL_DOMAIN} sentinel row (a leading space, like
 * {@code WorkloadConsoleConfig#GLOBAL_DOMAIN} / {@code PrincipalDomain.NO_DOMAIN}, so it
 * can never collide with a real issuer-derived domain).
 *
 * <ul>
 *   <li>{@link #granted} — the SUPERADMIN key. On a normal domain row this is "has this
 *       domain been granted the capability at all". On the GLOBAL row this SAME column
 *       IS the platform-wide kill switch — reusing one column for both purposes mirrors
 *       how {@code WorkloadConsoleConfig}'s GLOBAL row reuses
 *       {@code dangerous_tier_enabled} as the cluster-wide kill.</li>
 *   <li>{@link #enabled} — the domain ADMIN key: has THIS domain's admin opted in.
 *       Meaningless on the GLOBAL row (nothing reads it there).</li>
 * </ul>
 *
 * <p>Both ship DARK (false). {@link #active()} — GLOBAL.granted AND perDomain.granted AND
 * perDomain.enabled — is the two-tier predicate {@code DomainCapabilityService#isActive}
 * evaluates; an absent row of either kind is treated as {@code false} (fail-closed).
 */
public record DomainCapability(
        String id,
        String domain,
        String capability,
        boolean granted,
        boolean enabled,
        String updatedBy,
        Instant updatedAt,
        long generation) {

    /** The cluster-wide sentinel domain — a leading space mirrors
     *  {@code WorkloadConsoleConfig#GLOBAL_DOMAIN} / {@code PrincipalDomain.NO_DOMAIN} so it
     *  can never equal a real issuer-derived domain. */
    public static final String GLOBAL_DOMAIN = " global";

    /** The first (and so far only) capability key this table hosts: gates a user
     *  registering a mesh radio under their own name. */
    public static final String USER_MESH_DEVICES = "user-mesh-devices";

    /** Both per-row keys on: the SUPERADMIN grant AND the domain ADMIN opt-in. Only
     *  meaningful for a PER-DOMAIN row — the GLOBAL row's {@code enabled} is unused by
     *  the active predicate (see class doc). */
    public boolean active() {
        return granted && enabled;
    }
}
