package net.hugmesh.adminbff.workload;

/**
 * The WORKLOAD CONSOLE danger tier — the AUTHORITATIVE classification of every console
 * capability. The central {@link WorkloadAuthorizationFilter} predicate keys on the TIER,
 * <b>NEVER on the HTTP verb</b> (DESIGN AXIOM): a non-superadmin can never reach
 * {@link #RUNTIME_MUTATE} or {@link #DANGEROUS} regardless of method, and the GLOBAL
 * dangerous-tier kill (DECISION 5) is evaluated BEFORE the superadmin short-circuit so it
 * disables {@link #DANGEROUS} even for a superadmin.
 *
 * <ul>
 *   <li>{@link #READ} — ps/inspect(projected DTO)/stats/df/events/healthcheck + non-stream
 *       redacted logs (the log BODY is additionally gated on the grant's {@code log_access}
 *       flag). Reachable by an admin-read-when-granted (AR) AND a superadmin (SA).</li>
 *   <li>{@link #RUNTIME_MUTATE} — restart(=pod-delete) / kill-recreate. SA-only.</li>
 *   <li>{@link #DANGEROUS} — live log-stream / exec(read-only allowlist) / exec -it TTY /
 *       port-forward / lifecycle GitOps intents. SA-only AND globally gated on
 *       dangerous_tier_enabled (kill applies even to SA).</li>
 * </ul>
 */
public enum DangerTier {
    READ,
    RUNTIME_MUTATE,
    DANGEROUS
}
