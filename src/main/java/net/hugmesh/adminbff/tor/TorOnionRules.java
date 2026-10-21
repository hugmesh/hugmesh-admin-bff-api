package net.hugmesh.adminbff.tor;

import java.util.Optional;
import java.util.regex.Pattern;

/**
 * The value rules shared by both halves of the node Tor contract
 * (hugmesh-admin-bff-api#108; the node half is hugmesh-generator#583 / #599).
 *
 * <p>Every rule here MIRRORS what the node agent {@code /usr/sbin/hugmesh-tor-reconcile}
 * already accepts, so a value this BFF stores is a value the node will apply, never one it
 * silently ignores:
 * <ul>
 *   <li>{@link #UPSTREAM} is the agent's {@code _UPSTREAM_RE}
 *       ({@code ^([A-Za-z0-9.-]+|\[[0-9A-Fa-f:.]+\]):[0-9]{1,5}$}), plus a 1..65535 port
 *       range the agent does not check. Whitespace anywhere is refused (the agent trims
 *       only the ends and refuses inner whitespace).</li>
 *   <li>{@link #SLUG} is the agent's per-domain slug rule
 *       ({@code [a-z0-9][a-z0-9-]{0,62}}); a slug with a dot or inner whitespace is
 *       refused there, so it is refused here.</li>
 *   <li>{@link #ONION_V3} is a Tor v3 onion hostname: 56 base32 characters
 *       ({@code a-z2-7}) then {@code .onion}. The agent exports exactly the hostname file
 *       tor writes, which is lowercase.</li>
 * </ul>
 *
 * <p>Pure and side-effect free; no Spring, no I/O.
 */
public final class TorOnionRules {

    /** The node agent's upstream rule (its {@code _UPSTREAM_RE}). */
    public static final Pattern UPSTREAM =
            Pattern.compile("^([A-Za-z0-9.-]+|\\[[0-9A-Fa-f:.]+\\]):([0-9]{1,5})$");

    /** The node agent's per-domain slug rule. */
    public static final Pattern SLUG = Pattern.compile("^[a-z0-9][a-z0-9-]{0,62}$");

    /** A Tor v3 onion hostname (the content of a {@code hostname} file, trimmed). */
    public static final Pattern ONION_V3 = Pattern.compile("^[a-z2-7]{56}\\.onion$");

    /**
     * The tenancy domain key the PRIMARY onion serves. The primary onion is the mesh's own
     * door, registered in the gateway host map as {@code <onion>=default}
     * (hugmesh-gateway#39's writer contract), so {@code default} never gets a per-domain
     * stanza of its own.
     */
    public static final String DEFAULT_DOMAIN = "default";

    /** Upper bound on per-domain onions one node may report (and one export may carry). */
    public static final int MAX_DOMAINS = 64;

    private TorOnionRules() {
    }

    /** Why {@code upstream} cannot be written to {@code /etc/hugmesh/tor/upstream}, or empty. */
    public static Optional<String> upstreamRefusal(String upstream) {
        if (upstream == null || upstream.isEmpty()) {
            return Optional.of("upstream is empty");
        }
        var m = UPSTREAM.matcher(upstream);
        if (!m.matches()) {
            return Optional.of("upstream must be one host:port token (hostname, IPv4 or "
                    + "[IPv6]), with no whitespace — the node agent ignores anything else");
        }
        int port = Integer.parseInt(m.group(2));
        if (port < 1 || port > 65535) {
            return Optional.of("upstream port must be 1..65535");
        }
        return Optional.empty();
    }

    /** True iff {@code slug} is a per-domain slug the node agent will render a stanza for. */
    public static boolean isSlug(String slug) {
        return slug != null && SLUG.matcher(slug).matches();
    }

    /** True iff {@code onion} is a Tor v3 onion hostname. */
    public static boolean isOnionV3(String onion) {
        return onion != null && ONION_V3.matcher(onion).matches();
    }
}
