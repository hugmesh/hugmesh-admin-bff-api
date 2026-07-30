package systems.hugmesh.adminbff.sshissue;

import org.springframework.stereotype.Service;
import systems.hugmesh.adminbff.workload.WorkloadStepUpService;

/**
 * The STEP-UP gate for the PRIVILEGED admin SSH key-ISSUANCE paths: ISSUING a credential
 * (which mints a real Ed25519 keypair AND registers its fingerprint into a device_ssh_license
 * row — granting real SSH to a node), DOWNLOADING the one-time private key, and REVOKING a
 * credential. Each requires a fresh, deliberate re-confirmation (step-up MFA) ON TOP of the
 * role + own-domain checks — the same posture the platform takes for the workload-console
 * DANGEROUS tier, the cloud-backup restore, and the image-gen trigger/keys-download.
 *
 * <p><b>Reuses the platform's existing step-up mechanism.</b> Clone of
 * {@link systems.hugmesh.adminbff.imagegen.ImageGenStepUpGate}: rather than mint a parallel
 * token broker, this gate delegates to the existing {@link WorkloadStepUpService} (validate
 * {@code subject + token}). The controller reads the presented token from the
 * {@code X-SshKeyIssue-StepUp} header; a missing/invalid token is a clean 403 with a "requires
 * step-up" contract.
 *
 * <p><b>SECURITY REVIEW FLAG — step-up mint reachability.</b> The step-up token MINT
 * ({@link WorkloadStepUpService#mint}) is currently reachable on a SUPERADMIN-only path (the
 * workload console). This feature is SUPERADMIN-only in v1 (the controller @PreAuthorize is
 * {@code hasRole('SUPERADMIN')}), so the mint path already covers it — there is no ADMIN
 * widening here, unlike the image-gen gate. Should v1 later widen to ADMIN, this is the single
 * seam to wire the Casdoor-MFA generalized step-up authority ({@code amr/acr -> MFA_SATISFIED},
 * schema band 150-159) as the satisfying signal.
 */
@Service
public class SshKeyIssueStepUpGate {

    /** The header the controller reads the presented step-up token from. */
    public static final String STEP_UP_HEADER = "X-SshKeyIssue-StepUp";

    private final WorkloadStepUpService stepUp;

    public SshKeyIssueStepUpGate(WorkloadStepUpService stepUp) {
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
     * SSH key-ISSUANCE is a DEVICE op — the MFA leg satisfies the step-up re-confirmation, but
     * issuance still registers a fingerprint into a device_ssh_license row, so the
     * own-domain + license preconditions on the issuance path remain (downstream). The MFA leg
     * itself is license-INDEPENDENT (it never checks a license), so the device precondition is
     * unaffected. {@code mfaFresh} is gated on {@code app.casdoor.mfa.enabled} (false by
     * default) AND the freshness window.
     */
    public boolean isSatisfied(String subject, String stepUpToken, boolean mfaFresh) {
        return mfaFresh || isSatisfied(subject, stepUpToken);
    }
}
