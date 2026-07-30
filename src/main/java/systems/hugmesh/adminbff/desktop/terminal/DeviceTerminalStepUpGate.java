package systems.hugmesh.adminbff.desktop.terminal;

import org.springframework.stereotype.Service;
import systems.hugmesh.adminbff.workload.WorkloadStepUpService;

/**
 * The STEP-UP gate for the PRIVILEGED device-facing desktop paths that reach a shell/exec onto a
 * tenant device: the in-UI SSH TERMINAL (the {@link DeviceSshTerminalWebSocketHandler} gate-4) and
 * the REMOTE-INSTALL trigger. Both require a fresh, deliberate re-confirmation (step-up) ON TOP of
 * the role + own-domain + device-ssh-license checks — the same posture the platform takes for the
 * workload-console DANGEROUS tier, the SSH key-issuance leg, and the image-gen trigger/keys-download.
 *
 * <p><b>ONE header, ONE trust surface for terminal + install.</b> Clone of
 * {@link systems.hugmesh.adminbff.sshissue.SshKeyIssueStepUpGate} /
 * {@link systems.hugmesh.adminbff.imagegen.ImageGenStepUpGate}: rather than mint a parallel token
 * broker, this gate delegates to the existing {@link WorkloadStepUpService} (validate
 * {@code subject + token}). It deliberately REUSES the EXISTING
 * {@link DeviceSshTerminalWebSocketHandler#STEP_UP_HEADER} ({@code X-Device-Terminal-StepUp}) the
 * live WS handler already defines — a second {@code X-Desktop-StepUp} header was rejected so the
 * terminal and the remote-install present the SAME step-up token over the SAME header. A
 * missing/blank token is fail-closed: NOT satisfied.
 *
 * <p><b>The gate-4 unblocker.</b> The {@link WorkloadStepUpService#mint} broker is now reachable by
 * an ADMIN through {@link systems.hugmesh.adminbff.desktop.DesktopStepUpController}
 * ({@code POST /bff/admin/desktop/step-up}) — required because the WS handler's gate-4 accepts
 * ADMIN, so without an ADMIN-reachable mint an ADMIN could never satisfy step-up. The mint itself is
 * unchanged (leader-pinned + active-ssh-license precondition); only the CALLER widened.
 *
 * <p>TODO (Casdoor-MFA leg): also accept the validated JWT's {@code amr/acr -> MFA_SATISFIED}
 * authority (or an opaque {@code mfa_satisfied} session) as the satisfying signal once the
 * Casdoor-MFA schema band 150-159 lands. This is the single seam to wire that authority.
 */
@Service
public class DeviceTerminalStepUpGate {

    /**
     * The header the remote-install controller reads the presented step-up token from — the SAME
     * constant the live WS handler defines, so terminal + install share ONE step-up trust surface.
     */
    public static final String STEP_UP_HEADER = DeviceSshTerminalWebSocketHandler.STEP_UP_HEADER;

    private final WorkloadStepUpService stepUp;

    public DeviceTerminalStepUpGate(WorkloadStepUpService stepUp) {
        this.stepUp = stepUp;
    }

    /**
     * True iff {@code subject} presents a currently-valid step-up token. Fail-closed: a null/blank
     * subject or token is NOT satisfied (so a missing/blank header is a clean 403 even for an
     * otherwise-authorized ADMIN).
     */
    public boolean isSatisfied(String subject, String stepUpToken) {
        if (subject == null || subject.isBlank() || stepUpToken == null || stepUpToken.isBlank()) {
            return false;
        }
        return stepUp.validate(subject, stepUpToken);
    }

    /**
     * A5 UNIFIED step-up: satisfied if EITHER a valid {@link WorkloadStepUpService} token OR
     * a FRESH Casdoor-MFA stamp on the caller's opaque session ({@code mfaFresh}, computed by
     * {@link systems.hugmesh.authcore.casdoor.MfaStepUpService}). The two legs are CO-EQUAL.
     * Terminal + remote-install are DEVICE ops — the MFA leg satisfies the step-up
     * re-confirmation, but the device_ssh_license precondition for actually dialing the device
     * still lives DOWNSTREAM in the dial/remote-install service (the SSH-license registry), so
     * the MFA leg (which is license-INDEPENDENT) does NOT bypass the device license. {@code
     * mfaFresh} is gated on {@code app.casdoor.mfa.enabled} (false by default) AND the freshness
     * window.
     */
    public boolean isSatisfied(String subject, String stepUpToken, boolean mfaFresh) {
        return mfaFresh || isSatisfied(subject, stepUpToken);
    }

    /** Consume (single-use) the step-up token for {@code subject} after a successful authorized
     *  action so it cannot be replayed — mirrors the WS handler's {@code consume} on a real open. */
    public void consume(String subject) {
        if (subject != null && !subject.isBlank()) {
            stepUp.consume(subject);
        }
    }
}
