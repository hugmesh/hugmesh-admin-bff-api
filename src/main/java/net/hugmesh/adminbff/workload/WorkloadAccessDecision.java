package net.hugmesh.adminbff.workload;

/**
 * The outcome of the central WORKLOAD CONSOLE authorization predicate
 * ({@link WorkloadAuthorizationService#decide}). The {@link WorkloadAuthorizationFilter}
 * (and the per-heartbeat stream re-authz) act on this:
 *
 * <ul>
 *   <li>{@link #allow()} → ALLOW (request proceeds / stream stays open);</li>
 *   <li>{@code !allow} with {@link #notFound()} → 404 (no existence leak: the capability
 *       probe + a denied admin reach return 404, never 403, so the feature's existence is
 *       not revealed);</li>
 *   <li>{@code !allow} with {@code !notFound} → 403 (an authenticated principal who reached a
 *       gated tier they cannot use — e.g. the GLOBAL dangerous-tier kill, a missing step-up,
 *       an out-of-allowlist namespace probe).</li>
 * </ul>
 *
 * {@link #logAccess()} carries whether the matched grant opted into log BODIES (DECISION 4);
 * a log path with {@code logAccess=false} is denied even when the read itself is allowed.
 */
public record WorkloadAccessDecision(
        boolean allow,
        boolean notFound,
        String reason,
        boolean superadmin,
        boolean logAccess) {

    public static WorkloadAccessDecision allow(boolean superadmin, boolean logAccess) {
        return new WorkloadAccessDecision(true, false, "ok", superadmin, logAccess);
    }

    /** A 404 deny — used for the no-existence-leak paths (capability probe, denied admin). */
    public static WorkloadAccessDecision notFound(String reason) {
        return new WorkloadAccessDecision(false, true, reason, false, false);
    }

    /** A 403 deny — used for the explicit refusals (kill-switch, step-up, namespace probe). */
    public static WorkloadAccessDecision forbidden(String reason) {
        return new WorkloadAccessDecision(false, false, reason, false, false);
    }
}
