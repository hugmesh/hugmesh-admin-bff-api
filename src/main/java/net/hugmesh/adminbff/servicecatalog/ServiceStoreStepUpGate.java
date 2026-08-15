package net.hugmesh.adminbff.servicecatalog;

import org.springframework.stereotype.Service;
import net.hugmesh.adminbff.workload.AbstractStepUpGate;
import net.hugmesh.adminbff.workload.WorkloadStepUpService;

/**
 * The STEP-UP gate for the PRIVILEGED Service-Store wizard writes: SCAFFOLDING a new service (which
 * mints a starter codebase + a persisted intent for a brand) and FEDERATING a deployment (which
 * registers its UI into the federation manifest). Each requires a fresh, deliberate
 * re-confirmation (step-up MFA) ON TOP of the SUPERADMIN role — the same posture the platform takes
 * for the go-live wizard, the workload-console DANGEROUS tier, cloud-backup restore, the image-gen
 * trigger and SSH key-issuance.
 *
 * <p><b>Reuses the platform's existing step-up mechanism.</b> Its satisfy legs live in
 * {@link net.hugmesh.adminbff.workload.AbstractStepUpGate} (shared by all eight gates, so
 * a change to the legs cannot reach only some of them): rather than mint a parallel
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
public class ServiceStoreStepUpGate extends AbstractStepUpGate {

    /** The header the controller reads the presented step-up token from. */
    public static final String STEP_UP_HEADER = "X-ServiceStore-StepUp";

    public ServiceStoreStepUpGate(WorkloadStepUpService stepUp) {
        super(stepUp);
    }
}
