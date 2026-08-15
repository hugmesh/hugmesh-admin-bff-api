package net.hugmesh.adminbff.workload;

/**
 * The shared body of every per-feature step-up gate.
 *
 * <h2>Why this exists</h2>
 * Eight gates ({@code BackingService}, {@code Backup}, {@code DeviceTerminal}, {@code GoLive},
 * {@code ImageGen}, {@code PhoneLock}, {@code ServiceStore}, {@code SshKeyIssue}) carried
 * CHARACTER-IDENTICAL copies of the same twelve lines — seven of them byte-for-byte once the
 * package, class name and retry-header value are normalised away. That is not merely
 * repetitive: the copies had already DRIFTED. {@code DeviceTerminalStepUpGate} rejected a
 * BLANK subject; the other seven checked only for {@code null}. Somebody hardened one gate and
 * the other seven never learned about it, which is the exact failure mode this codebase keeps
 * paying for.
 *
 * <p>This base harmonises on the STRICTER of the two: a blank subject is not satisfied. That is
 * defense in depth rather than a live fix — {@code WorkloadStepUpService.validate} would look up
 * {@code tokens.get("")} and miss unless an entry had been minted under a blank subject, and the
 * one mint path that could do so is {@code SUPERADMIN}-gated and needs a JWT with an empty
 * {@code sub}. (The mint side is closed at source in the same change.)
 *
 * <h2>What deliberately did NOT move</h2>
 * Each gate keeps its own {@code STEP_UP_HEADER} constant, its own {@code @Service} identity and
 * its own type. Controllers inject gates BY TYPE, and both structural scanners
 * ({@code StepUpEmissionSeamTest}, {@code StepUpConsumeSeamTest}) discover gates through the
 * retry-header VALUE SHAPE {@code X-<flavour>-StepUp}. Collapsing the eight types into one
 * parameterised service would have re-pointed 19 injection sites and pulled the anchor out from
 * under both guards. The duplicated LOGIC was the hazard; the per-flavour identity is the
 * contract.
 */
public abstract class AbstractStepUpGate {

    private final WorkloadStepUpService stepUp;

    protected AbstractStepUpGate(WorkloadStepUpService stepUp) {
        this.stepUp = stepUp;
    }

    /**
     * True iff {@code subject} presents a currently-valid workload step-up token. Fail-closed: a
     * null/blank subject or a null/blank token is NOT satisfied.
     *
     * <p>This is the token-only primitive. Production call sites use the three-arg overload; this
     * one exists so a caller that must require a workload token specifically still can.
     */
    public boolean isSatisfied(String subject, String stepUpToken) {
        if (subject == null || subject.isBlank() || stepUpToken == null || stepUpToken.isBlank()) {
            return false;
        }
        return stepUp.validate(subject, stepUpToken);
    }

    /**
     * A5 UNIFIED step-up: satisfied by EITHER a valid {@link WorkloadStepUpService} token OR a
     * FRESH Casdoor-MFA stamp on the caller's opaque session ({@code mfaFresh}, computed by
     * {@code MfaStepUpService}). The two legs are CO-EQUAL and the MFA leg is
     * license-INDEPENDENT — it satisfies the step-up re-confirmation only; every downstream
     * precondition (own-domain, device licence, role) still applies at its own site.
     *
     * <p>{@code mfaFresh} is gated on {@code app.casdoor.mfa.enabled} (false by default) AND the
     * freshness window, so with the flag dark this collapses to the token leg exactly as before.
     */
    public boolean isSatisfied(String subject, String stepUpToken, boolean mfaFresh) {
        return mfaFresh || isSatisfied(subject, stepUpToken);
    }

    /**
     * Consume the workload step-up token for {@code subject} (single use). No-op for a
     * null/blank subject. Exposed for gates whose call site consumes the token leg explicitly.
     */
    protected void consumeToken(String subject) {
        if (subject != null && !subject.isBlank()) {
            stepUp.consume(subject);
        }
    }
}
