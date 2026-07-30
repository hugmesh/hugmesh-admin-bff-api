package systems.hugmesh.adminbff.desktop.terminal;

import org.junit.jupiter.api.Test;
import systems.hugmesh.adminbff.workload.WorkloadStepUpService;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit coverage for the {@link DeviceTerminalStepUpGate} — the ONE step-up trust surface for the
 * device-facing desktop paths (terminal + remote-install). Fail-closed on null/blank; delegates to
 * the shared {@link WorkloadStepUpService}; cross-subject tokens do not satisfy; reuses the SAME
 * header constant the live WS handler defines (no second X-Desktop-StepUp header).
 */
class DeviceTerminalStepUpGateTest {

    private final WorkloadStepUpService broker = mock(WorkloadStepUpService.class);
    private final DeviceTerminalStepUpGate gate = new DeviceTerminalStepUpGate(broker);

    @Test
    void reusesTheLiveWsHandlerHeader_notASecondHeader() {
        // ONE header, ONE trust surface for terminal + install (decision: no X-Desktop-StepUp).
        assertThat(DeviceTerminalStepUpGate.STEP_UP_HEADER)
                .isEqualTo("X-Device-Terminal-StepUp")
                .isEqualTo(DeviceSshTerminalWebSocketHandler.STEP_UP_HEADER);
    }

    @Test
    void nullSubject_notSatisfied_neverCallsBroker() {
        assertThat(gate.isSatisfied(null, "tok")).isFalse();
        verify(broker, never()).validate(eq(null), eq("tok"));
    }

    @Test
    void blankSubject_notSatisfied() {
        assertThat(gate.isSatisfied("  ", "tok")).isFalse();
        verify(broker, never()).validate("  ", "tok");
    }

    @Test
    void nullToken_notSatisfied() {
        assertThat(gate.isSatisfied("admin-x", null)).isFalse();
        verify(broker, never()).validate("admin-x", null);
    }

    @Test
    void blankToken_notSatisfied() {
        assertThat(gate.isSatisfied("admin-x", "   ")).isFalse();
        verify(broker, never()).validate("admin-x", "   ");
    }

    @Test
    void validTokenForSubject_satisfied() {
        when(broker.validate("admin-x", "good")).thenReturn(true);
        assertThat(gate.isSatisfied("admin-x", "good")).isTrue();
    }

    @Test
    void crossSubjectToken_rejected() {
        // a token minted for admin-x is not valid for admin-y (the broker is per-subject).
        when(broker.validate("admin-y", "tok-for-x")).thenReturn(false);
        assertThat(gate.isSatisfied("admin-y", "tok-for-x")).isFalse();
    }

    @Test
    void consume_delegatesToBroker_forNonBlankSubject() {
        gate.consume("admin-x");
        verify(broker).consume("admin-x");
    }

    @Test
    void consume_noopForBlankSubject() {
        gate.consume("  ");
        verify(broker, never()).consume("  ");
    }
}
