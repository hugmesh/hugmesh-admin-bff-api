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

    /** The first capability key this table hosts: gates a user registering a mesh radio
     *  under their own name. */
    public static final String USER_MESH_DEVICES = "user-mesh-devices";

    /**
     * Gates whether a domain's ADMIN may grant a USER the external-client roles
     * ({@code ROLE_MATRIX_EXTERNAL_CLIENT} / {@code ROLE_MASTODON_EXTERNAL_CLIENT}) — the
     * capability that lets a user point a third-party Matrix/Mastodon app at their
     * account instead of only the in-mesh web clients.
     *
     * <p>Enforced in {@code AdminController#grantRole}, which is the ONLY path that can
     * assign those two roles. That placement is deliberate: putting the check on a
     * bespoke external-client endpoint instead would leave the generic
     * {@code POST /bff/admin/roles/ROLE_MATRIX_EXTERNAL_CLIENT/{user}} as an unguarded
     * way around the switch, i.e. a superadmin control that only appears to control
     * anything.
     *
     * <p>Same two-tier shape as every other key here — SUPERADMIN grants the domain,
     * the domain's ADMIN opts in, and the {@link #GLOBAL_DOMAIN} row is the platform-wide
     * kill. Ships DARK: with no rows written, external-client grants are refused.
     */
    public static final String EXTERNAL_CLIENT_GRANT = "external-client-grant";

    /**
     * Gates whether a domain gets its OWN Tor onion (decision 68 = A on
     * hugmesh-generator#347: a Tor domain is its own HiddenService stanza fronting the same
     * gateway). Consumed by {@code net.hugmesh.adminbff.tor.TorExportService}, which turns
     * the ACTIVE rows into the {@code /etc/hugmesh/tor/domains} list of every node's signed
     * Tor export (hugmesh-admin-bff-api#108). The row's {@code domain} is the slug the node
     * names its onion by, so it must match the node agent's {@code [a-z0-9][a-z0-9-]{0,62}};
     * a row that does not is left out of the export.
     *
     * <p>Unlike the other keys, the {@link #GLOBAL_DOMAIN} row is NOT seeded: until a
     * SUPERADMIN writes it, the export does not manage the domains file at all, so a list
     * the image baked stays in force. Once written, {@code granted=false} withdraws every
     * per-domain onion and {@code granted=true} makes the active rows authoritative.
     */
    public static final String TOR_ONION = "tor-onion";

    /** Both per-row keys on: the SUPERADMIN grant AND the domain ADMIN opt-in. Only
     *  meaningful for a PER-DOMAIN row — the GLOBAL row's {@code enabled} is unused by
     *  the active predicate (see class doc). */
    public boolean active() {
        return granted && enabled;
    }
}
