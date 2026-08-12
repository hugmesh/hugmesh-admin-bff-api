package net.hugmesh.adminbff.phone;

import reactor.core.publisher.Mono;

/**
 * The AGGREGATE lock enforcement seam the {@link PhoneManagementService} calls after it has
 * already recorded the authoritative lock/unlock in the DB. It fans a lock/unlock command out
 * to every {@link PhoneLockLeg} and reduces their {@link PhoneLockLeg.LegOutcome}s to ONE
 * {@link Outcome} whose {@link Outcome#propagationState()} the service stamps onto
 * {@code phone_device.lock_propagation_state}.
 *
 * <p><b>The control-plane state is ALWAYS authoritative.</b> This enforcer NEVER throws and
 * NEVER decides whether the lock "took" — the lock row is already written. It only reports how
 * far the side effect propagated:
 * <ul>
 *   <li>{@code APPLIED} — iff EVERY enabled leg applied and NO leg is disabled;</li>
 *   <li>{@code DEGRADED} — any leg disabled (flag off) OR an enabled leg was best-effort
 *       unreachable. Both legs off (the default) degrades with the documented console reason;</li>
 *   <li>{@code FAILED} — an enabled leg's channel actively rejected the command (hard error).</li>
 * </ul>
 */
public interface PhoneLockEnforcer {

    /** Enforce a LOCK across all legs; resolves to the aggregate {@link Outcome} (never throws). */
    Mono<Outcome> enforceLock(PhoneDevice device);

    /** Enforce an UNLOCK across all legs; resolves to the aggregate {@link Outcome} (never throws). */
    Mono<Outcome> enforceUnlock(PhoneDevice device);

    /**
     * The aggregate propagation outcome. {@code state} maps 1:1 to the three non-pending
     * {@code lock_propagation_state} values; {@code reason} is a short NON-SECRET diagnostic
     * surfaced in logs (and, for the all-disabled default, the operator-facing console hint).
     */
    record Outcome(State state, String reason) {

        public enum State { APPLIED, DEGRADED, FAILED }

        public static Outcome applied()               { return new Outcome(State.APPLIED, null); }
        public static Outcome degraded(String reason) { return new Outcome(State.DEGRADED, reason); }
        public static Outcome failed(String reason)   { return new Outcome(State.FAILED, reason); }

        public boolean isApplied()  { return state == State.APPLIED; }
        public boolean isDegraded() { return state == State.DEGRADED; }
        public boolean isFailed()   { return state == State.FAILED; }

        /** The {@code lock_propagation_state} column value for this outcome. */
        public String propagationState() {
            return switch (state) {
                case APPLIED -> PhoneDevice.PROP_APPLIED;
                case DEGRADED -> PhoneDevice.PROP_DEGRADED;
                case FAILED -> PhoneDevice.PROP_FAILED;
            };
        }
    }
}
