package systems.hugmesh.adminbff.imagegen;

import org.springframework.stereotype.Service;
import systems.hugmesh.adminbff.workload.WorkloadStepUpService;

/**
 * The STEP-UP gate for the PRIVILEGED image-generation paths: TRIGGERING a build (which
 * provisions a real device image + can seed dial material) and DOWNLOADING the SSH-keys bundle.
 * Both require a fresh, deliberate re-confirmation (step-up MFA) ON TOP of the role + own-domain
 * checks — the same posture the platform takes for the workload-console DANGEROUS tier and the
 * cloud-backup restore.
 *
 * <p><b>Reuses the platform's existing step-up mechanism.</b> Rather than mint a parallel token
 * broker, this gate delegates to the existing {@link WorkloadStepUpService} (validate
 * {@code subject + token}). The controller reads the presented token from the
 * {@code X-ImageGen-StepUp} header; a missing/invalid token is a clean 403 with a "requires
 * step-up" contract.
 *
 * <p><b>SECURITY REVIEW FLAG — ADMIN step-up widening.</b> The step-up token MINT
 * ({@link WorkloadStepUpService#mint}) is currently reachable on a SUPERADMIN-only path
 * (the workload console). This feature requires step-up for an <em>ADMIN</em> action
 * (own-domain image build + keys download), which WIDENS who must be able to obtain a step-up
 * token to ADMINs. Until the Casdoor-MFA generalized step-up authority lands (schema band
 * 150-159: {@code amr/acr -> MFA_SATISFIED}), an ADMIN has no first-class way to mint this
 * token, so on a launch-enabled deployment the operator must either (a) expose a mint path to
 * ADMINs, or (b) wire the MFA authority here as the satisfying signal. This is the single seam
 * to swap in the MFA authority and is called out for security review in the PR.
 */
@Service
public class ImageGenStepUpGate {

    /** The header the controller reads the presented step-up token from. */
    public static final String STEP_UP_HEADER = "X-ImageGen-StepUp";

    private final WorkloadStepUpService stepUp;

    public ImageGenStepUpGate(WorkloadStepUpService stepUp) {
        this.stepUp = stepUp;
    }

    /**
     * True iff {@code subject} presents a currently-valid step-up token. Fail-closed: a null
     * subject/token is NOT satisfied.
     *
     * <p>TODO (Casdoor-MFA leg): also return true when the request's validated JWT carries the
     * {@code MFA_SATISFIED} authority (amr/acr) or the opaque session is {@code mfa_satisfied}.
     */
    public boolean isSatisfied(String subject, String stepUpToken) {
        if (subject == null || stepUpToken == null || stepUpToken.isBlank()) {
            return false;
        }
        return stepUp.validate(subject, stepUpToken);
    }

    /**
     * A5 UNIFIED step-up: satisfied if EITHER a valid {@link WorkloadStepUpService} token OR
     * a FRESH Casdoor-MFA stamp on the caller's opaque session ({@code mfaFresh}, computed by
     * {@link systems.hugmesh.authcore.casdoor.MfaStepUpService}). The two legs are CO-EQUAL.
     * The MFA leg is LICENSE-INDEPENDENT, which is precisely the seam this gate's
     * SECURITY-REVIEW-FLAG called out: an ADMIN with no first-class workload-step-up mint path
     * can now satisfy step-up via a fresh MFA stamp. The DEVICE precondition for the image
     * BUILD itself still lives downstream (own-domain + image-build service guards) — the MFA
     * leg only satisfies the step-up re-confirmation. {@code mfaFresh} is gated on
     * {@code app.casdoor.mfa.enabled} (false by default) AND the freshness window.
     */
    public boolean isSatisfied(String subject, String stepUpToken, boolean mfaFresh) {
        return mfaFresh || isSatisfied(subject, stepUpToken);
    }
}
