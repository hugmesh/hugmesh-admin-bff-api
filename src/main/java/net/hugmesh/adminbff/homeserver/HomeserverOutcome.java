package net.hugmesh.adminbff.homeserver;

/**
 * The outcome of a homeserver account-state effect (akkoma suspend/unsuspend,
 * tuwunel deactivate/activate), carried back to the reconcile loop so the tick is
 * auditable regardless of whether the external admin call was actually made.
 * Mirrors the announcement {@code AkkomaOutcome} / mod-bff {@code BlockOutcome}
 * stub-seam convention exactly.
 *
 * <ul>
 *   <li>{@code STUBBED} ({@link #stubbed()}) — the external admin HTTP call was
 *       deliberately NOT made (the homeserver admin seam is unconfirmed /
 *       {@code homeserver.admin.enabled=false}). The desired-state row is still
 *       authoritative; the loop maps STUBBED to a {@code pending} propagation_state
 *       so a later tick (once the seam is wired on) re-applies it.</li>
 *   <li>{@code OK} ({@link #ok()}) — the homeserver account state was applied (or was
 *       already in the desired state — the calls are idempotent).</li>
 *   <li>{@code degraded:<reason>} ({@link #degraded(String)}) — the call was
 *       attempted and failed (or the circuit breaker is open); NEVER hard-fail the
 *       tick. The row's propagation_state becomes {@code failed} and the next tick
 *       retries.</li>
 * </ul>
 *
 * <p>By contract the loop treats only {@link #isOk()} as "applied"; STUBBED and
 * degraded both leave the suspension reconcilable on the next tick so flipping the
 * seam on later is config-only.
 */
public record HomeserverOutcome(String result) {

    public static HomeserverOutcome stubbed() {
        return new HomeserverOutcome("stubbed");
    }

    public static HomeserverOutcome ok() {
        return new HomeserverOutcome("ok");
    }

    public static HomeserverOutcome degraded(String reason) {
        return new HomeserverOutcome("degraded:" + reason);
    }

    public boolean isStubbed() {
        return "stubbed".equals(result);
    }

    public boolean isOk() {
        return "ok".equals(result);
    }
}
