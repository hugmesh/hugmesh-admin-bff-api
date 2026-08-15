package net.hugmesh.adminbff.sshissue;

import org.springframework.stereotype.Service;
import net.hugmesh.adminbff.workload.AbstractStepUpGate;
import net.hugmesh.adminbff.workload.WorkloadStepUpService;

/**
 * The STEP-UP gate for the PRIVILEGED admin SSH key-ISSUANCE paths: ISSUING a credential
 * (which mints a real Ed25519 keypair AND registers its fingerprint into a device_ssh_license
 * row — granting real SSH to a node), DOWNLOADING the one-time private key, and REVOKING a
 * credential. Each requires a fresh, deliberate re-confirmation (step-up MFA) ON TOP of the
 * role + own-domain checks — the same posture the platform takes for the workload-console
 * DANGEROUS tier, the cloud-backup restore, and the image-gen trigger/keys-download.
 *
 * <p><b>Reuses the platform's existing step-up mechanism.</b> Its satisfy legs live in
 * {@link net.hugmesh.adminbff.workload.AbstractStepUpGate} (shared by all eight gates, so
 * a change to the legs cannot reach only some of them): rather than mint a parallel
 * token broker, this gate delegates to the existing {@link WorkloadStepUpService} (validate
 * {@code subject + token}). The controller reads the presented token from the
 * {@code X-SshKeyIssue-StepUp} header; a missing/invalid token is a clean 403 with a "requires
 * step-up" contract.
 *
 * <p><b>SECURITY REVIEW FLAG — step-up mint reachability.</b> The step-up token MINT
 * ({@link WorkloadStepUpService#mint}) is currently reachable on a SUPERADMIN-only path (the
 * workload console). This feature is SUPERADMIN-only in v1 (the controller @PreAuthorize is
 * {@code hasRole('SUPERADMIN')}), so the mint path already covers it — there is no ADMIN
 * widening here, unlike the image-gen gate. Should v1 later widen to ADMIN, no wiring is
 * needed: the Casdoor-MFA leg is ALREADY a co-equal satisfying signal here (the 3-arg
 * {@link #isSatisfied(String, String, boolean)}), so an ADMIN completing an MFA challenge
 * would satisfy this gate without a mint path. (It is not derived from {@code amr}/{@code acr}
 * — that mechanism never existed; see {@code Roles.isMfaSatisfied}.)
 */
@Service
public class SshKeyIssueStepUpGate extends AbstractStepUpGate {

    /** The header the controller reads the presented step-up token from. */
    public static final String STEP_UP_HEADER = "X-SshKeyIssue-StepUp";

    public SshKeyIssueStepUpGate(WorkloadStepUpService stepUp) {
        super(stepUp);
    }
}
