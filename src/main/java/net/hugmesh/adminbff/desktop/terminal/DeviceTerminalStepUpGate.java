package net.hugmesh.adminbff.desktop.terminal;

import org.springframework.stereotype.Service;
import net.hugmesh.adminbff.workload.AbstractStepUpGate;
import net.hugmesh.adminbff.workload.WorkloadStepUpService;

/**
 * The STEP-UP gate for the PRIVILEGED device-facing desktop paths that reach a shell/exec onto a
 * tenant device: the in-UI SSH TERMINAL (the {@link DeviceSshTerminalWebSocketHandler} gate-4) and
 * the REMOTE-INSTALL trigger. Both require a fresh, deliberate re-confirmation (step-up) ON TOP of
 * the role + own-domain + device-ssh-license checks — the same posture the platform takes for the
 * workload-console DANGEROUS tier, the SSH key-issuance leg, and the image-gen trigger/keys-download.
 *
 * <p><b>ONE header, ONE trust surface for terminal + install.</b> Its satisfy legs live in
 * {@link net.hugmesh.adminbff.workload.AbstractStepUpGate} (shared by all eight gates, so
 * a change to the legs cannot reach only some of them): rather than mint a parallel token
 * broker, this gate delegates to the existing {@link WorkloadStepUpService} (validate
 * {@code subject + token}). It deliberately REUSES the EXISTING
 * {@link DeviceSshTerminalWebSocketHandler#STEP_UP_HEADER} ({@code X-Device-Terminal-StepUp}) the
 * live WS handler already defines — a second {@code X-Desktop-StepUp} header was rejected so the
 * terminal and the remote-install present the SAME step-up token over the SAME header. A
 * missing/blank token is fail-closed: NOT satisfied.
 *
 * <p><b>The gate-4 unblocker.</b> The {@link WorkloadStepUpService#mint} broker is now reachable by
 * an ADMIN through {@link net.hugmesh.adminbff.desktop.DesktopStepUpController}
 * ({@code POST /bff/admin/desktop/step-up}) — required because the WS handler's gate-4 accepts
 * ADMIN, so without an ADMIN-reachable mint an ADMIN could never satisfy step-up. The mint itself is
 * unchanged (leader-pinned + active-ssh-license precondition); only the CALLER widened.
 *
 * <p>A fresh MFA stamp on the opaque {@code bff_} session is accepted as a co-equal satisfying
 * signal, via the 3-arg {@code isSatisfied(subject, stepUpToken, mfaFresh)}. No code derives
 * {@code MFA_SATISFIED} from {@code amr}/{@code acr}; it comes from the BFF-written
 * {@code mfa_satisfied_at} claim (see {@code Roles.isMfaSatisfied}).
 */
@Service
public class DeviceTerminalStepUpGate extends AbstractStepUpGate {

    /** The header the controller reads the presented step-up token from. */
    public static final String STEP_UP_HEADER = DeviceSshTerminalWebSocketHandler.STEP_UP_HEADER;

    public DeviceTerminalStepUpGate(WorkloadStepUpService stepUp) {
        super(stepUp);
    }

    /**
     * Consume the workload step-up token for {@code subject} (single use). Kept as public API
     * because {@code DeviceSshTerminalWebSocketHandler} and {@code DesktopDialAdminController}
     * consume the token leg explicitly at the commit point.
     */
    public void consume(String subject) {
        consumeToken(subject);
    }
}
