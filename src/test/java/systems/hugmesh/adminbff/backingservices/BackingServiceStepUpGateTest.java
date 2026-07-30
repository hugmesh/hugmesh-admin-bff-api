package systems.hugmesh.adminbff.backingservices;

import org.junit.jupiter.api.Test;
import systems.hugmesh.adminbff.workload.WorkloadStepUpService;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit coverage for the REAL {@link BackingServiceStepUpGate} — the step-up trust surface for the
 * privileged managed/self-hosted mode-change path. The controller suite mocks this gate, so this
 * class is the ONLY place its actual logic runs: fail-closed on null/blank; delegates to the shared
 * {@link WorkloadStepUpService}; and — the A5 UNIFIED lever that must not silently open — the
 * three-arg {@code isSatisfied(subject, token, mfaFresh)} is genuinely {@code mfaFresh OR token},
 * with the {@code mfaFresh} leg able to bypass an absent/invalid token (and NOTHING else does).
 */
class BackingServiceStepUpGateTest {

    private final WorkloadStepUpService broker = mock(WorkloadStepUpService.class);
    private final BackingServiceStepUpGate gate = new BackingServiceStepUpGate(broker);

    @Test
    void headerConstantIsTheBackingServicesHeader() {
        assertThat(BackingServiceStepUpGate.STEP_UP_HEADER).isEqualTo("X-BackingServices-StepUp");
    }

    // ── two-arg (token-only) leg ────────────────────────────────────────────────────────────

    @Test
    void nullSubject_notSatisfied_neverCallsBroker() {
        assertThat(gate.isSatisfied(null, "tok")).isFalse();
        verify(broker, never()).validate(any(), anyString());
    }

    @Test
    void nullOrBlankToken_notSatisfied_neverCallsBroker() {
        assertThat(gate.isSatisfied("alice", null)).isFalse();
        assertThat(gate.isSatisfied("alice", "   ")).isFalse();
        verify(broker, never()).validate(anyString(), any());
    }

    @Test
    void validToken_delegatesToBroker() {
        when(broker.validate("alice", "good")).thenReturn(true);
        assertThat(gate.isSatisfied("alice", "good")).isTrue();
        verify(broker).validate("alice", "good");
    }

    @Test
    void invalidToken_notSatisfied() {
        when(broker.validate("alice", "bad")).thenReturn(false);
        assertThat(gate.isSatisfied("alice", "bad")).isFalse();
    }

    // ── three-arg A5-unified leg (mfaFresh OR token) — the actual bypass logic ──────────────

    @Test
    void mfaFresh_satisfies_evenWithNoValidToken_andNeverNeedsTheBroker() {
        // The MFA leg is co-equal: a fresh Casdoor-MFA stamp satisfies on its own, so a null/absent
        // step-up token must NOT block it. This is the lever the controller suite only mocks.
        assertThat(gate.isSatisfied("alice", null, true)).isTrue();
        assertThat(gate.isSatisfied("alice", "", true)).isTrue();
        verify(broker, never()).validate(anyString(), any());
    }

    @Test
    void mfaNotFresh_fallsBackToTheToken_valid() {
        when(broker.validate("alice", "good")).thenReturn(true);
        assertThat(gate.isSatisfied("alice", "good", false)).isTrue();
    }

    @Test
    void mfaNotFresh_andInvalidToken_notSatisfied() {
        when(broker.validate("alice", "bad")).thenReturn(false);
        assertThat(gate.isSatisfied("alice", "bad", false)).isFalse();
        // Neither leg opens: no MFA, no valid token → fail-closed.
        assertThat(gate.isSatisfied("alice", null, false)).isFalse();
    }
}
