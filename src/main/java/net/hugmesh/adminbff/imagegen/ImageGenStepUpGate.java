package net.hugmesh.adminbff.imagegen;

import org.springframework.stereotype.Service;
import net.hugmesh.adminbff.workload.AbstractStepUpGate;
import net.hugmesh.adminbff.workload.WorkloadStepUpService;

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
 * token to ADMINs. That gap is CLOSED, by option (b) of the two this javadoc used to offer:
 * the MFA authority is wired here as a co-equal satisfying signal (the 3-arg
 * {@link #isSatisfied(String, String, boolean)}), so an ADMIN who completes a Casdoor MFA
 * challenge satisfies this gate without any step-up token. <b>Option (a) — exposing a
 * workload-step-up mint path to ADMINs — is therefore NOT required, and should not be added
 * on the strength of this comment.</b> (The old wording also named a mechanism that never
 * existed: {@code MFA_SATISFIED} is not derived from {@code amr}/{@code acr}.)
 *
 * <p>⚠ One real precondition remains for a launch-enabled deployment: the MFA leg is gated on
 * {@code app.casdoor.mfa.enabled} AND the freshness window. ADMINs on an opaque {@code bff_}
 * session are stamped synchronously and are unaffected; an ADMIN presenting a RAW Casdoor JWT
 * must RE-MINT after completing MFA to pick the stamp up (nothing forces that refresh — see
 * the generator's {@code docs/MFA-ROLLOUT.md} §2.4 for the full carrier taxonomy).
 */
@Service
public class ImageGenStepUpGate extends AbstractStepUpGate {

    /** The header the controller reads the presented step-up token from. */
    public static final String STEP_UP_HEADER = "X-ImageGen-StepUp";

    public ImageGenStepUpGate(WorkloadStepUpService stepUp) {
        super(stepUp);
    }
}
