package systems.hugmesh.adminbff.casdoor;
import systems.hugmesh.authcore.casdoor.*;

import org.junit.jupiter.api.Test;
import systems.hugmesh.adminbff.cloudbackup.BackupStepUpGate;
import systems.hugmesh.adminbff.desktop.terminal.DeviceTerminalStepUpGate;
import systems.hugmesh.adminbff.imagegen.ImageGenStepUpGate;
import systems.hugmesh.adminbff.sshissue.SshKeyIssueStepUpGate;
import systems.hugmesh.adminbff.workload.WorkloadStepUpService;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * A5 unified step-up — the {@code isSatisfied(subject, token, mfaFresh)} leg across ALL FOUR
 * gates (Backup / Device-Terminal / ImageGen / SshKeyIssue). Proves the two legs are CO-EQUAL:
 * <ul>
 *   <li>a valid {@link WorkloadStepUpService} token satisfies (mfaFresh=false);</li>
 *   <li>a FRESH MFA stamp satisfies EVEN with no/invalid token (license-INDEPENDENT — the gate
 *       never consults a license; the token leg's license precondition lives at MINT, the device
 *       precondition lives downstream);</li>
 *   <li>NEITHER -> not satisfied (fail-closed);</li>
 *   <li>mfaFresh is the caller-supplied, flag-gated boolean — when the MFA leg is dark
 *       (mfaFresh always false) ONLY the token leg works (today's behaviour).</li>
 * </ul>
 */
class UnifiedStepUpGateTest {

    private final WorkloadStepUpService broker = mock(WorkloadStepUpService.class);

    private final BackupStepUpGate backup = new BackupStepUpGate(broker);
    private final ImageGenStepUpGate imageGen = new ImageGenStepUpGate(broker);
    private final SshKeyIssueStepUpGate sshKey = new SshKeyIssueStepUpGate(broker);
    private final DeviceTerminalStepUpGate terminal = new DeviceTerminalStepUpGate(broker);

    @Test
    void tokenLeg_satisfies_whenMfaDark() {
        when(broker.validate("admin-x", "tok")).thenReturn(true);
        // mfaFresh=false (leg dark) -> the token leg is the only satisfier and it works.
        assertThat(backup.isSatisfied("admin-x", "tok", false)).isTrue();
        assertThat(imageGen.isSatisfied("admin-x", "tok", false)).isTrue();
        assertThat(sshKey.isSatisfied("admin-x", "tok", false)).isTrue();
        assertThat(terminal.isSatisfied("admin-x", "tok", false)).isTrue();
    }

    @Test
    void mfaLeg_satisfies_withNoToken_licenseIndependent() {
        // No workload token at all (null/blank), but a FRESH MFA stamp -> satisfied. The gate
        // never checks a license, so this is license-INDEPENDENT (the backup-restore superadmin
        // non-device op can step up with no device_ssh_license).
        assertThat(backup.isSatisfied("admin-x", null, true)).isTrue();
        assertThat(imageGen.isSatisfied("admin-x", "", true)).isTrue();
        assertThat(sshKey.isSatisfied("admin-x", null, true)).isTrue();
        assertThat(terminal.isSatisfied("admin-x", null, true)).isTrue();
    }

    @Test
    void mfaLeg_satisfies_evenWhenTokenInvalid() {
        when(broker.validate("admin-x", "bad")).thenReturn(false);
        // The two legs are an OR: a fresh MFA stamp satisfies even though the token is invalid.
        assertThat(backup.isSatisfied("admin-x", "bad", true)).isTrue();
        assertThat(terminal.isSatisfied("admin-x", "bad", true)).isTrue();
    }

    @Test
    void neitherLeg_failsClosed() {
        when(broker.validate("admin-x", "bad")).thenReturn(false);
        assertThat(backup.isSatisfied("admin-x", "bad", false)).isFalse();
        assertThat(imageGen.isSatisfied("admin-x", "bad", false)).isFalse();
        assertThat(sshKey.isSatisfied("admin-x", "bad", false)).isFalse();
        assertThat(terminal.isSatisfied("admin-x", "bad", false)).isFalse();
        // and with no token at all and no MFA -> still closed.
        assertThat(backup.isSatisfied("admin-x", null, false)).isFalse();
        assertThat(terminal.isSatisfied("admin-x", null, false)).isFalse();
    }

    @Test
    void twoArgLeg_unchanged_backwardCompatible() {
        // The legacy 2-arg gate is untouched (still pure token check).
        when(broker.validate("admin-x", "tok")).thenReturn(true);
        assertThat(backup.isSatisfied("admin-x", "tok")).isTrue();
        assertThat(backup.isSatisfied("admin-x", "nope")).isFalse();
    }
}
