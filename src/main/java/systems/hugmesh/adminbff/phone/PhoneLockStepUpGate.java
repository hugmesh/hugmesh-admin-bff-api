package systems.hugmesh.adminbff.phone;

import org.springframework.stereotype.Service;
import systems.hugmesh.adminbff.workload.WorkloadStepUpService;

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
 * systems.hugmesh.authcore.casdoor.MfaStepUpService}, gated on {@code app.casdoor.mfa.enabled},
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
 *       {@code ADMIN+SUPERADMIN} ({@link systems.hugmesh.adminbff.desktop.DesktopStepUpController})
 *       and SUPERADMIN-only ({@code WorkloadSuperadminController}), and both also require an
 *       active {@code device_ssh_license}. So a fleet owner's step-up is the <b>MFA leg</b> —
 *       fleet lock/unlock is reachable only where {@code app.casdoor.mfa.enabled=true}. This is
 *       intentional: a fleet customer re-confirms with MFA, not with an operator SSH license.</li>
 * </ul>
 *
 * <p>Descendant of {@link systems.hugmesh.adminbff.sshissue.SshKeyIssueStepUpGate}: rather
 * than mint a parallel token broker, this gate delegates to the existing {@link
 * WorkloadStepUpService} for the token leg and {@code MfaStepUpService} for the MFA leg.
 */
@Service
public class PhoneLockStepUpGate {

    /** The header the controller reads the presented step-up token from. */
    public static final String STEP_UP_HEADER = "X-PhoneLock-StepUp";

    private final WorkloadStepUpService stepUp;

    public PhoneLockStepUpGate(WorkloadStepUpService stepUp) {
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
     * UNIFIED step-up: satisfied if EITHER a valid {@link WorkloadStepUpService} token OR a
     * FRESH Casdoor-MFA stamp on the caller's opaque session ({@code mfaFresh}, computed by
     * {@link systems.hugmesh.authcore.casdoor.MfaStepUpService}). The two legs are CO-EQUAL.
     * The step-up satisfies ONLY the re-confirmation; the SUPERADMIN role + PrincipalDomain
     * scope + the state-machine preconditions (managed-only lock) remain enforced downstream.
     * {@code mfaFresh} is gated on {@code app.casdoor.mfa.enabled} (false by default) AND the
     * freshness window.
     */
    public boolean isSatisfied(String subject, String stepUpToken, boolean mfaFresh) {
        return mfaFresh || isSatisfied(subject, stepUpToken);
    }
}
