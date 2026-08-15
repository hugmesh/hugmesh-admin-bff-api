package net.hugmesh.adminbff.golive;

import org.springframework.stereotype.Service;
import net.hugmesh.adminbff.workload.AbstractStepUpGate;
import net.hugmesh.adminbff.workload.WorkloadStepUpService;

/**
 * The STEP-UP gate for the PRIVILEGED go-live wizard paths: RECORDING a go-live intent (which,
 * once the host agent verifies + applies it, exposes an entire brand to the public internet)
 * and WITHDRAWING one. Each requires a fresh, deliberate re-confirmation (step-up MFA) ON TOP
 * of the SUPERADMIN role — the same posture the platform takes for the workload-console
 * DANGEROUS tier, the cloud-backup restore, the image-gen trigger and SSH key-issuance. The
 * pinned design is explicit: "no unattended/headless auto-go-live — a human confirm step is
 * the security boundary"; this gate is that boundary's server-side half.
 *
 * <p><b>Reuses the platform's existing step-up mechanism.</b> Its satisfy legs live in
 * {@link net.hugmesh.adminbff.workload.AbstractStepUpGate} (shared by all eight gates, so
 * a change to the legs cannot reach only some of them): rather than mint a parallel
 * token broker, this gate delegates to the existing {@link WorkloadStepUpService} (validate
 * {@code subject + token}). The controller reads the presented token from the
 * {@code X-GoLive-StepUp} header; a missing/invalid token is a clean 403 with a "requires
 * step-up" contract.
 *
 * <p><b>Step-up mint reachability.</b> The step-up token MINT ({@link
 * WorkloadStepUpService#mint}) is reachable on a SUPERADMIN-only path (the workload console),
 * and this feature is SUPERADMIN-only in v1 (the controller {@code @PreAuthorize} is
 * {@code hasRole('SUPERADMIN')}), so the mint path already covers it — no ADMIN widening.
 */
@Service
public class GoLiveStepUpGate extends AbstractStepUpGate {

    /** The header the controller reads the presented step-up token from. */
    public static final String STEP_UP_HEADER = "X-GoLive-StepUp";

    public GoLiveStepUpGate(WorkloadStepUpService stepUp) {
        super(stepUp);
    }
}
