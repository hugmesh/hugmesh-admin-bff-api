package systems.hugmesh.adminbff.servicecatalog;

import org.springframework.stereotype.Service;
import systems.hugmesh.adminbff.workload.WorkloadStepUpService;

/**
 * The STEP-UP gate for the PRIVILEGED Service-Store wizard writes: SCAFFOLDING a new service (which
 * mints a starter codebase + a persisted intent for a brand) and FEDERATING a deployment (which
 * registers its UI into the federation manifest). Each requires a fresh, deliberate
 * re-confirmation (step-up MFA) ON TOP of the SUPERADMIN role — the same posture the platform takes
 * for the go-live wizard, the workload-console DANGEROUS tier, cloud-backup restore, the image-gen
 * trigger and SSH key-issuance.
 *
 * <p><b>Reuses the platform's existing step-up mechanism.</b> Clone of
 * {@link systems.hugmesh.adminbff.golive.GoLiveStepUpGate} /
 * {@link systems.hugmesh.adminbff.sshissue.SshKeyIssueStepUpGate}: rather than mint a parallel
 * token broker, this gate delegates to the existing {@link WorkloadStepUpService} (validate
 * {@code subject + token}). The controller reads the presented token from the
 * {@code X-ServiceStore-StepUp} header; a missing/invalid token is a clean 403 with a "requires
 * step-up" contract.
 *
 * <p><b>Step-up mint reachability.</b> The step-up token MINT ({@link WorkloadStepUpService#mint})
 * is reachable on a SUPERADMIN-only path (the workload console), and this surface is SUPERADMIN-only
 * (the controller {@code @PreAuthorize} is {@code hasRole('SUPERADMIN')}), so the mint path already
 * covers it — no ADMIN widening.
 */
@Service
public class ServiceStoreStepUpGate {

    /** The header the controller reads the presented step-up token from. */
    public static final String STEP_UP_HEADER = "X-ServiceStore-StepUp";

    private final WorkloadStepUpService stepUp;

    public ServiceStoreStepUpGate(WorkloadStepUpService stepUp) {
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
     * {@link systems.hugmesh.authcore.casdoor.MfaStepUpService}). The two legs are CO-EQUAL,
     * exactly as on the go-live / image-gen / ssh-issue gates. {@code mfaFresh} is gated on
     * {@code app.casdoor.mfa.enabled} (false by default) AND the freshness window.
     */
    public boolean isSatisfied(String subject, String stepUpToken, boolean mfaFresh) {
        return mfaFresh || isSatisfied(subject, stepUpToken);
    }
}
