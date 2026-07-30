package systems.hugmesh.adminbff.cloudbackup;

import org.springframework.stereotype.Service;
import systems.hugmesh.adminbff.workload.WorkloadStepUpService;

/**
 * The STEP-UP gate for the PRIVILEGED restore path ({@code POST
 * /bff/admin/cloud-backups/{id}/restore}). A restore overwrites live cluster state, so it
 * requires a fresh, deliberate re-confirmation (step-up MFA) ON TOP of the role + domain
 * checks — exactly the posture the platform already takes for the workload-console DANGEROUS
 * tier (exec / log-stream / mutations).
 *
 * <p><b>Reuses the platform's existing step-up mechanism.</b> Rather than mint a parallel
 * token broker, this gate delegates to the existing {@link WorkloadStepUpService} — the
 * short-TTL, leader-pinned, SSH-license-bound token broker (validate {@code subject + token}).
 * The restore controller reads the presented token from the {@code X-Backup-StepUp} header and
 * calls {@link #isSatisfied(String, String)}; a missing/invalid token is a clean 403 with a
 * "requires step-up" contract (the {@code error} body says so), so a client knows to obtain a
 * step-up token first.
 *
 * <p>TODO (Casdoor-MFA leg, schema band 150-159): once the Casdoor MFA build lands its
 * generalized step-up authority ({@code amr/acr -> MFA_SATISFIED}, the {@code mfa_satisfied}
 * opaque-session stamp), this gate should ALSO accept that authority as satisfying step-up —
 * the design memo lists "restore" among the generalized step-up operations. Until then the
 * workload step-up token IS the step-up mechanism (no separate stub broker), and this gate is
 * the single seam to swap in the MFA authority.
 */
@Service
public class BackupStepUpGate {

    /** The header the restore controller reads the presented step-up token from. */
    public static final String STEP_UP_HEADER = "X-Backup-StepUp";

    private final WorkloadStepUpService stepUp;

    public BackupStepUpGate(WorkloadStepUpService stepUp) {
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
     * A5 UNIFIED step-up: satisfied if EITHER a valid {@link WorkloadStepUpService} token
     * (the {@link #isSatisfied(String, String)} leg) OR a FRESH Casdoor-MFA stamp on the
     * caller's opaque session ({@code mfaFresh}, computed by
     * {@link systems.hugmesh.authcore.casdoor.MfaStepUpService}). The two legs are
     * CO-EQUAL. The MFA leg is LICENSE-INDEPENDENT — restore is a SUPERADMIN NON-device op,
     * so a fresh MFA stamp satisfies with NO device_ssh_license. {@code mfaFresh} is already
     * gated on {@code app.casdoor.mfa.enabled} (false by default -> only the token leg works)
     * AND the freshness window, so a stale stamp arrives here as {@code false}.
     */
    public boolean isSatisfied(String subject, String stepUpToken, boolean mfaFresh) {
        return mfaFresh || isSatisfied(subject, stepUpToken);
    }
}
