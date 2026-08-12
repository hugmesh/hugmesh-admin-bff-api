package net.hugmesh.adminbff.workload;

import java.time.Instant;

/**
 * A WORKLOAD CONSOLE master-config row — the kill-switch state. One row per domain plus a
 * GLOBAL {@link #GLOBAL_DOMAIN} sentinel row (a leading space, like
 * {@code PrincipalDomain.NO_DOMAIN}, so it can never collide with a real issuer-derived domain).
 *
 * <ul>
 *   <li>{@link #adminEnabled} — ships dark (false). Even a granted admin sees nothing until
 *       a superadmin flips this (DECISION 4).</li>
 *   <li>{@link #dangerousTierEnabled} — ships dark (false). The GLOBAL row's flag is the
 *       cluster-wide kill of exec / log-stream / runtime-mutations that applies EVEN to a
 *       SUPERADMIN, evaluated BEFORE the superadmin short-circuit (DECISION 5).</li>
 * </ul>
 */
public record WorkloadConsoleConfig(
        String id,
        String domain,
        boolean adminEnabled,
        boolean dangerousTierEnabled,
        String updatedBy,
        Instant updatedAt,
        long generation) {

    /** The cluster-wide sentinel domain — a leading space mirrors PrincipalDomain.NO_DOMAIN so
     *  it can never equal a real issuer-derived domain. */
    public static final String GLOBAL_DOMAIN = " global";
}
