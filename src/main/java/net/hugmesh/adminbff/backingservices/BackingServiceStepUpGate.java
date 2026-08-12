package net.hugmesh.adminbff.backingservices;

import org.springframework.stereotype.Service;
import net.hugmesh.adminbff.workload.WorkloadStepUpService;

/**
 * The STEP-UP gate for the PRIVILEGED backing-services path: RECORDING a mode intent (which,
 * once the generator/effector leg converges it, re-points a whole brand's database / object
 * store / mail / event bus at a hosted cloud endpoint and prunes the in-mesh workload). Each
 * mutation requires a fresh, deliberate re-confirmation (step-up MFA) ON TOP of the SUPERADMIN
 * role — the same posture the platform takes for the go-live wizard, the cloud-backup restore,
 * the image-gen trigger and SSH key-issuance.
 *
 * <p><b>Reuses the platform's existing step-up mechanism.</b> Direct clone of
 * {@link net.hugmesh.adminbff.golive.GoLiveStepUpGate}: rather than mint a parallel
 * token broker, this gate delegates to the existing {@link WorkloadStepUpService} (validate
 * {@code subject + token}). The controller reads the presented token from the
 * {@code X-BackingServices-StepUp} header; a missing/invalid token is a clean 403 with a
 * "requires step-up" contract.
 *
 * <p><b>Step-up mint reachability.</b> The step-up token MINT ({@link
 * WorkloadStepUpService#mint}) is reachable on a SUPERADMIN-only path (the workload console),
 * and this feature is SUPERADMIN-only (the controller {@code @PreAuthorize} is
 * {@code hasRole('SUPERADMIN')}), so the mint path already covers it — no ADMIN widening.
 */
@Service
public class BackingServiceStepUpGate {

    /** The header the controller reads the presented step-up token from. */
    public static final String STEP_UP_HEADER = "X-BackingServices-StepUp";

    private final WorkloadStepUpService stepUp;

    public BackingServiceStepUpGate(WorkloadStepUpService stepUp) {
        this.stepUp = stepUp;
    }

    /**
     * True iff {@code subject} presents a currently-valid step-up token. Fail-closed: a null
     * subject/token is NOT satisfied.
     */
    public boolean isSatisfied(String subject, String stepUpToken) {
        if (subject == null || stepUpToken == null || stepUpToken.isBlank()) {
            return false;
        }
        return stepUp.validate(subject, stepUpToken);
    }

    /**
     * A5 UNIFIED step-up: satisfied if EITHER a valid {@link WorkloadStepUpService} token OR a
     * FRESH Casdoor-MFA stamp on the caller's opaque session ({@code mfaFresh}, computed by
     * {@link net.hugmesh.authcore.casdoor.MfaStepUpService}). The two legs are CO-EQUAL,
     * exactly as on the go-live / image-gen / ssh-issue gates. {@code mfaFresh} is gated on
     * {@code app.casdoor.mfa.enabled} (false by default) AND the freshness window.
     */
    public boolean isSatisfied(String subject, String stepUpToken, boolean mfaFresh) {
        return mfaFresh || isSatisfied(subject, stepUpToken);
    }
}
