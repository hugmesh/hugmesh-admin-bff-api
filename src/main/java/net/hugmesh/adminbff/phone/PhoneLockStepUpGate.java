package net.hugmesh.adminbff.phone;

import org.springframework.stereotype.Service;
import net.hugmesh.adminbff.workload.AbstractStepUpGate;
import net.hugmesh.adminbff.workload.WorkloadStepUpService;

/**
 * The STEP-UP gate for the PRIVILEGED phone management + lockout mutations: MARKING a phone
 * managed/BYOD ({@code PUT .../management}), LOCKING it ({@code POST .../lock}) and UNLOCKING
 * it ({@code POST .../unlock}). Each requires a fresh, deliberate re-confirmation (step-up) ON
 * TOP of the role check — the same posture the platform takes for SSH key-issuance, the
 * workload-console DANGEROUS tier, and the image-gen trigger.
 *
 * <p><b>Two co-equal step-up legs.</b> {@link #isSatisfied(String, String, boolean)} is met by
 * EITHER a valid {@link WorkloadStepUpService} token (presented in the {@code X-PhoneLock-StepUp}
 * header) OR a FRESH Casdoor-MFA stamp on the caller's opaque session (computed by {@link
 * net.hugmesh.authcore.casdoor.MfaStepUpService}, gated on {@code app.casdoor.mfa.enabled},
 * dark by default). A missing/invalid step-up on BOTH legs is a clean, fail-closed 403.
 *
 * <p><b>Two planes reuse this one gate — mind which leg each plane can actually satisfy:</b>
 * <ul>
 *   <li>the SUPERADMIN plane ({@link PhoneManagementSuperadminController}) can use EITHER leg —
 *       a SUPERADMIN can mint a workload token ({@code POST /bff/superadmin/workload/step-up})
 *       or satisfy MFA;</li>
 *   <li>the FLEET-OWNER plane ({@link PhoneFleetOwnerController},
 *       {@code hasAnyRole('FLEET_ADMIN','ADMIN','SUPERADMIN')}) is reachable by a pure
 *       {@code FLEET_ADMIN} who CANNOT mint a workload token: the only mint endpoints are
 *       {@code ADMIN+SUPERADMIN} ({@link net.hugmesh.adminbff.desktop.DesktopStepUpController})
 *       and SUPERADMIN-only ({@code WorkloadSuperadminController}), and both also require an
 *       active {@code device_ssh_license}. So a fleet owner's step-up is the <b>MFA leg</b> —
 *       fleet lock/unlock is reachable only where {@code app.casdoor.mfa.enabled=true}. This is
 *       intentional: a fleet customer re-confirms with MFA, not with an operator SSH license.</li>
 * </ul>
 *
 * <p>Descendant of {@link net.hugmesh.adminbff.sshissue.SshKeyIssueStepUpGate}: rather
 * than mint a parallel token broker, this gate delegates to the existing {@link
 * WorkloadStepUpService} for the token leg and {@code MfaStepUpService} for the MFA leg.
 */
@Service
public class PhoneLockStepUpGate extends AbstractStepUpGate {

    /** The header the controller reads the presented step-up token from. */
    public static final String STEP_UP_HEADER = "X-PhoneLock-StepUp";

    public PhoneLockStepUpGate(WorkloadStepUpService stepUp) {
        super(stepUp);
    }
}
