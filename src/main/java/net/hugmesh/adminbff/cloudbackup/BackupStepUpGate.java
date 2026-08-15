package net.hugmesh.adminbff.cloudbackup;

import org.springframework.stereotype.Service;
import net.hugmesh.adminbff.workload.AbstractStepUpGate;
import net.hugmesh.adminbff.workload.WorkloadStepUpService;

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
 * <p>DONE (was a TODO for the Casdoor-MFA leg): this gate DOES accept a fresh MFA stamp as
 * satisfying step-up, via the 3-arg {@link #isSatisfied(String, String, boolean)} — "restore"
 * is one of the generalized step-up operations the design memo named. The stamp arrives on the
 * opaque {@code bff_} session; it is not derived from {@code amr}/{@code acr}, which no code
 * reads. Alongside it the workload step-up token remains a co-equal step-up mechanism (no
 * separate stub broker); this gate is the single seam for both.
 */
@Service
public class BackupStepUpGate extends AbstractStepUpGate {

    /** The header the controller reads the presented step-up token from. */
    public static final String STEP_UP_HEADER = "X-Backup-StepUp";

    public BackupStepUpGate(WorkloadStepUpService stepUp) {
        super(stepUp);
    }
}
