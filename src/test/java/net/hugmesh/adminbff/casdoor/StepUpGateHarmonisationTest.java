package net.hugmesh.adminbff.casdoor;

import org.junit.jupiter.api.Test;
import net.hugmesh.adminbff.backingservices.BackingServiceStepUpGate;
import net.hugmesh.adminbff.cloudbackup.BackupStepUpGate;
import net.hugmesh.adminbff.desktop.terminal.DeviceTerminalStepUpGate;
import net.hugmesh.adminbff.golive.GoLiveStepUpGate;
import net.hugmesh.adminbff.imagegen.ImageGenStepUpGate;
import net.hugmesh.adminbff.phone.PhoneLockStepUpGate;
import net.hugmesh.adminbff.servicecatalog.ServiceStoreStepUpGate;
import net.hugmesh.adminbff.sshissue.SshKeyIssueStepUpGate;
import net.hugmesh.adminbff.workload.AbstractStepUpGate;
import net.hugmesh.adminbff.workload.WorkloadStepUpService;

import java.util.LinkedHashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Every step-up gate must behave IDENTICALLY on the shared legs.
 *
 * <h2>Why this test exists</h2>
 * The eight gates used to hold character-identical copies of the same twelve lines, and the
 * copies had already drifted: {@code DeviceTerminalStepUpGate} rejected a BLANK subject while
 * the other seven checked only {@code null}. One gate was hardened and the other seven never
 * heard about it. {@link AbstractStepUpGate} now holds that logic once, harmonised on the
 * stricter variant — and this test pins the harmony so a future gate that re-implements the
 * legs locally, instead of inheriting them, is caught rather than merely reviewed.
 *
 * <p>The enumeration is deliberately EXPLICIT rather than reflective: a reflective sweep would
 * silently shrink to zero if the package moved, and pass. If a ninth gate is added it must be
 * added here, which is the point.
 */
class StepUpGateHarmonisationTest {

    private final WorkloadStepUpService stepUp = mock(WorkloadStepUpService.class);

    /** Every gate, by flavour, so a failure message names the offender. */
    private Map<String, AbstractStepUpGate> allGates() {
        Map<String, AbstractStepUpGate> gates = new LinkedHashMap<>();
        gates.put("BackingService", new BackingServiceStepUpGate(stepUp));
        gates.put("Backup", new BackupStepUpGate(stepUp));
        gates.put("DeviceTerminal", new DeviceTerminalStepUpGate(stepUp));
        gates.put("GoLive", new GoLiveStepUpGate(stepUp));
        gates.put("ImageGen", new ImageGenStepUpGate(stepUp));
        gates.put("PhoneLock", new PhoneLockStepUpGate(stepUp));
        gates.put("ServiceStore", new ServiceStoreStepUpGate(stepUp));
        gates.put("SshKeyIssue", new SshKeyIssueStepUpGate(stepUp));
        return gates;
    }

    @Test
    void everyGateRejectsABlankSubject_theDivergenceThatUsedToExist() {
        when(stepUp.validate(any(), any())).thenReturn(true);   // would satisfy if reached
        allGates().forEach((flavour, gate) -> {
            assertThat(gate.isSatisfied("", "tok"))
                    .as("%s must reject a BLANK subject (7 of 8 gates used to accept it)", flavour)
                    .isFalse();
            assertThat(gate.isSatisfied("   ", "tok"))
                    .as("%s must reject a whitespace-only subject", flavour).isFalse();
        });
        // The stricter check must short-circuit BEFORE the token lookup, not merely return false
        // after it — otherwise a blank subject still probes the token map.
        verify(stepUp, never()).validate(eq(""), any());
    }

    @Test
    void everyGateFailsClosedOnNullInputs() {
        when(stepUp.validate(any(), any())).thenReturn(true);
        allGates().forEach((flavour, gate) -> {
            assertThat(gate.isSatisfied(null, "tok")).as("%s null subject", flavour).isFalse();
            assertThat(gate.isSatisfied("admin", null)).as("%s null token", flavour).isFalse();
            assertThat(gate.isSatisfied("admin", "")).as("%s blank token", flavour).isFalse();
        });
    }

    @Test
    void everyGateTreatsTheMfaLegAsCoEqual_andLicenseIndependent() {
        when(stepUp.validate(any(), any())).thenReturn(false);  // token leg cannot satisfy
        allGates().forEach((flavour, gate) -> assertThat(gate.isSatisfied("admin-x", null, true))
                .as("%s: a fresh MFA stamp alone must satisfy, with no token at all", flavour)
                .isTrue());
    }

    @Test
    void everyGateFailsClosedWhenNeitherLegSatisfies() {
        when(stepUp.validate(any(), any())).thenReturn(false);
        allGates().forEach((flavour, gate) -> assertThat(gate.isSatisfied("admin-x", "bad", false))
                .as("%s: no valid token and no fresh MFA must be DENIED", flavour).isFalse());
    }

    @Test
    void everyGateStillCarriesItsOwnDistinctRetryHeader() {
        // The per-flavour identity is the contract both structural scanners key on; the refactor
        // shared the LOGIC and must not have collapsed the FLAVOURS.
        Map<String, String> headers = new LinkedHashMap<>();
        headers.put("BackingService", BackingServiceStepUpGate.STEP_UP_HEADER);
        headers.put("Backup", BackupStepUpGate.STEP_UP_HEADER);
        headers.put("DeviceTerminal", DeviceTerminalStepUpGate.STEP_UP_HEADER);
        headers.put("GoLive", GoLiveStepUpGate.STEP_UP_HEADER);
        headers.put("ImageGen", ImageGenStepUpGate.STEP_UP_HEADER);
        headers.put("PhoneLock", PhoneLockStepUpGate.STEP_UP_HEADER);
        headers.put("ServiceStore", ServiceStoreStepUpGate.STEP_UP_HEADER);
        headers.put("SshKeyIssue", SshKeyIssueStepUpGate.STEP_UP_HEADER);

        assertThat(headers.values()).as("every gate keeps a DISTINCT retry header")
                .doesNotHaveDuplicates().hasSize(allGates().size());
        assertThat(headers.values()).allSatisfy(h -> assertThat(h)
                .as("the X-<flavour>-StepUp shape is what both scanners discover gates by")
                .matches("X-[A-Za-z0-9-]{1,60}-StepUp"));
    }

    private static String eq(String s) {
        return org.mockito.ArgumentMatchers.eq(s);
    }
}
