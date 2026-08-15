package net.hugmesh.adminbff.backingservices;

import org.springframework.stereotype.Service;
import net.hugmesh.adminbff.workload.AbstractStepUpGate;
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
public class BackingServiceStepUpGate extends AbstractStepUpGate {

    /** The header the controller reads the presented step-up token from. */
    public static final String STEP_UP_HEADER = "X-BackingServices-StepUp";

    public BackingServiceStepUpGate(WorkloadStepUpService stepUp) {
        super(stepUp);
    }
}
