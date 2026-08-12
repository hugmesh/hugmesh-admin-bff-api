package net.hugmesh.adminbff.phone;

import reactor.core.publisher.Mono;

/**
 * ONE enforcement leg of a phone lock/unlock — the seam that carries a control-plane lock
 * decision out to a real device-affecting channel. Mirrors {@link
 * net.hugmesh.adminbff.device.HeadscalePolicyClient}: an interface with a REAL
 * flag-gated impl and a cluster-less no-op default, so the enforcement contract is fully
 * exercisable with no live infra.
 *
 * <p>Two legs exist ({@link HeadwindDpcLockClient} device-owner DPC lock,
 * {@link PhoneMeshDenyClient} headscale ACL phone-deny); {@link PhoneLockEnforcer} aggregates
 * their {@link LegOutcome}s into a single propagation state. A leg NEVER throws — an
 * unreachable/rejected channel resolves to a {@link LegOutcome}, because the AUTHORITATIVE
 * lock state is the DB row, never the side effect: the control plane must record the lock
 * regardless of whether any leg landed.
 */
public interface PhoneLockLeg {

    /** Short, stable leg name for the aggregate's diagnostic reason (never a secret). */
    String name();

    /**
     * Whether this leg should fire for {@code device}, given its DEVICE-REPORTED MDM provider
     * (changeset 307). The {@link DefaultPhoneLockEnforcer} fans lock/unlock ONLY to legs whose
     * {@code appliesTo} is true, so a provider-specific DPC leg (Headwind vs Azure Intune) fires
     * only for the matching provider while the platform-side mesh-deny leg — a headscale cut
     * that is provider-INDEPENDENT — applies to every device.
     *
     * <p>Default: {@code true} (provider-independent). The two DPC-family legs override this to
     * match {@link PhoneDevice#effectiveMdmProvider()}; the mesh-deny legs keep the default.
     */
    default boolean appliesTo(PhoneDevice device) {
        return true;
    }

    /** Command this leg to LOCK the device. Never throws; resolves to a {@link LegOutcome}. */
    Mono<LegOutcome> lock(PhoneDevice device);

    /** Command this leg to UNLOCK the device. Never throws; resolves to a {@link LegOutcome}. */
    Mono<LegOutcome> unlock(PhoneDevice device);

    /**
     * The outcome of a single leg's push. {@code applied} = the channel accepted the command;
     * {@code disabled} = this is the no-op leg (flag off, no call issued); {@code unreachable}
     * = an ENABLED leg made a best-effort call that could not reach the channel (transport /
     * timeout — degrades, does not fail); {@code failed} = an ENABLED leg's channel actively
     * REJECTED the command (a hard error — the enforcement definitively did not apply).
     * {@code detail} is a short NON-SECRET diagnostic for logs (never a token/body).
     */
    record LegOutcome(Result result, String detail) {

        public enum Result { APPLIED, DISABLED, UNREACHABLE, FAILED }

        public static LegOutcome applied() { return new LegOutcome(Result.APPLIED, null); }
        public static LegOutcome disabled(String detail) { return new LegOutcome(Result.DISABLED, detail); }
        public static LegOutcome unreachable(String detail) { return new LegOutcome(Result.UNREACHABLE, detail); }
        public static LegOutcome failed(String detail) { return new LegOutcome(Result.FAILED, detail); }

        public boolean isApplied()     { return result == Result.APPLIED; }
        public boolean isDisabled()    { return result == Result.DISABLED; }
        public boolean isUnreachable() { return result == Result.UNREACHABLE; }
        public boolean isFailed()      { return result == Result.FAILED; }
    }
}
