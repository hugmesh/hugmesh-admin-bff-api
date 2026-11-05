package net.hugmesh.adminbff.meshtoken;

import org.springframework.stereotype.Service;
import net.hugmesh.adminbff.workload.AbstractStepUpGate;
import net.hugmesh.adminbff.workload.WorkloadStepUpService;

/**
 * The step-up gate for ISSUING a HugMesh token: one token is a headscale pre-auth key plus a
 * signed grant of a role (and possibly shell access), so every issue needs a fresh, deliberate
 * re-confirmation on top of the role and own-domain checks — the same posture as
 * {@link net.hugmesh.adminbff.sshissue.SshKeyIssueStepUpGate}.
 *
 * <p>The legs live in {@link AbstractStepUpGate}: a valid {@link WorkloadStepUpService} token
 * (whose mint is SUPERADMIN-only) OR a fresh Casdoor-MFA stamp. An ADMIN therefore satisfies the
 * gate only through the MFA leg, which requires {@code app.casdoor.mfa.enabled}; with MFA dark
 * only a SUPERADMIN can issue. That is deliberate and is not widened here.
 */
@Service
public class MeshTokenStepUpGate extends AbstractStepUpGate {

    /** The header the controller reads the presented step-up token from. */
    public static final String STEP_UP_HEADER = "X-MeshToken-StepUp";

    public MeshTokenStepUpGate(WorkloadStepUpService stepUp) {
        super(stepUp);
    }
}
