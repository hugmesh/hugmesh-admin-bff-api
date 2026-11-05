package net.hugmesh.adminbff.mfa;

import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.List;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

/** The merge rules of {@link MfaRequirement}: strictest grace, intersected methods, fail closed. */
class MfaRequirementTest {

    private static final Duration PLATFORM = Duration.ofMinutes(10);

    private static RoleMfaPolicy policy(String role, boolean required, List<String> methods, long grace) {
        return new RoleMfaPolicy("brandx", role, required, methods, grace, true, false, "alice", null);
    }

    // ── required ──────────────────────────────────────────────────────────────────

    @Test
    void noRequiredParticipant_isNone() {
        MfaRequirement r = MfaRequirement.merge(List.of(
                policy("user", false, List.of("otp"), 5),
                policy("mod", false, List.of(), 0)));
        assertThat(r).isSameAs(MfaRequirement.NONE);
        assertThat(r.required()).isFalse();
    }

    @Test
    void anUnrequiredRole_contributesNothing_toTheMerge() {
        // user is not required: its tight grace and narrow methods must not bite.
        MfaRequirement r = MfaRequirement.merge(List.of(
                policy("user", false, List.of("recovery"), 1),
                policy("admin", true, List.of(), 0)));
        assertThat(r.required()).isTrue();
        assertThat(r.graceSeconds()).isZero();
        assertThat(r.platformWindowApplies()).isTrue();
        assertThat(r.methodsConstrained()).isFalse();
    }

    // ── grace ─────────────────────────────────────────────────────────────────────

    @Test
    void grace_isTheSmallestPositive_andZeroRecordsThePlatformWindow() {
        MfaRequirement r = MfaRequirement.merge(List.of(
                policy("admin", true, List.of(), 3600),
                policy("mod", true, List.of(), 300),
                policy("superadmin", true, List.of(), 0)));
        assertThat(r.graceSeconds()).isEqualTo(300L);
        assertThat(r.platformWindowApplies()).isTrue();
    }

    @Test
    void window_zeroGrace_isThePlatformWindow() {
        assertThat(MfaRequirement.merge(List.of(policy("admin", true, List.of(), 0))).window(PLATFORM))
                .isEqualTo(PLATFORM);
        // A missing or nonsense platform window degrades to the 10m default, as MfaStepUpService does.
        assertThat(MfaRequirement.UNKNOWN.window(null)).isEqualTo(Duration.ofMinutes(10));
        assertThat(MfaRequirement.UNKNOWN.window(Duration.ZERO)).isEqualTo(Duration.ofMinutes(10));
    }

    @Test
    void window_positiveGraceAlone_isThatGrace_evenWhenLongerThanThePlatformWindow() {
        MfaRequirement r = MfaRequirement.merge(List.of(policy("admin", true, List.of(), 3600)));
        assertThat(r.window(PLATFORM)).isEqualTo(Duration.ofSeconds(3600));
        assertThat(r.platformWindowApplies()).isFalse();
    }

    @Test
    void window_positiveGraceShorterThanPlatform_isTheGrace() {
        MfaRequirement r = MfaRequirement.merge(List.of(policy("admin", true, List.of(), 120)));
        assertThat(r.window(PLATFORM)).isEqualTo(Duration.ofSeconds(120));
    }

    @Test
    void window_aSiblingOnThePlatformWindow_capsALongerGrace_butNotAShorterOne() {
        MfaRequirement longer = MfaRequirement.merge(List.of(
                policy("admin", true, List.of(), 3600), policy("mod", true, List.of(), 0)));
        assertThat(longer.window(PLATFORM)).as("platform (10m) is stricter than 1h").isEqualTo(PLATFORM);

        MfaRequirement shorter = MfaRequirement.merge(List.of(
                policy("admin", true, List.of(), 60), policy("mod", true, List.of(), 0)));
        assertThat(shorter.window(PLATFORM)).as("60s is stricter than the platform").isEqualTo(Duration.ofSeconds(60));
    }

    // ── methods ───────────────────────────────────────────────────────────────────

    @Test
    void methods_unconstrained_allowsAnything_includingAStampWithNoMethod() {
        MfaRequirement r = MfaRequirement.merge(List.of(policy("admin", true, List.of(), 0)));
        assertThat(r.methodsConstrained()).isFalse();
        assertThat(r.allowsMethod("otp")).isTrue();
        assertThat(r.allowsMethod(null)).isTrue();
        assertThat(r.allowsMethod("")).isTrue();
    }

    @Test
    void methods_constrained_acceptsOnlyTheListedFactors_caseInsensitively() {
        MfaRequirement r = MfaRequirement.merge(List.of(policy("admin", true, List.of("webauthn", "otp"), 0)));
        assertThat(r.methodsConstrained()).isTrue();
        assertThat(r.methods()).containsExactlyInAnyOrder("webauthn", "otp");
        assertThat(r.allowsMethod("otp")).isTrue();
        assertThat(r.allowsMethod("WebAuthn")).isTrue();
        assertThat(r.allowsMethod(" otp ")).isTrue();
        assertThat(r.allowsMethod("recovery")).isFalse();
    }

    @Test
    void methods_constrained_failsClosedOnAStampThatRecordedNoMethod() {
        MfaRequirement r = MfaRequirement.merge(List.of(policy("admin", true, List.of("otp"), 0)));
        assertThat(r.allowsMethod(null)).isFalse();
        assertThat(r.allowsMethod("")).isFalse();
        assertThat(r.allowsMethod("   ")).isFalse();
    }

    @Test
    void methods_areIntersected_acrossConstrainedParticipants_andAnyListConstrainsNothing() {
        MfaRequirement r = MfaRequirement.merge(List.of(
                policy("admin", true, List.of("webauthn", "otp"), 0),
                policy("mod", true, List.of("otp", "recovery"), 0),
                policy("superadmin", true, List.of(), 0)));
        assertThat(r.methods()).containsExactly("otp");
        assertThat(r.allowsMethod("otp")).isTrue();
        assertThat(r.allowsMethod("webauthn")).isFalse();
        assertThat(r.allowsMethod("recovery")).isFalse();
    }

    @Test
    void anEmptyIntersection_isUnsatisfiable_andDeniesEveryFactor() {
        MfaRequirement r = MfaRequirement.merge(List.of(
                policy("admin", true, List.of("webauthn"), 0),
                policy("mod", true, List.of("otp"), 0)));
        assertThat(r.methodsConstrained()).isTrue();
        assertThat(r.methods()).isEmpty();
        for (String m : Set.of("webauthn", "otp", "recovery")) {
            assertThat(r.allowsMethod(m)).as(m).isFalse();
        }
    }

    @Test
    void unknown_isRequiredOnThePlatformWindow_withAnyMethod() {
        assertThat(MfaRequirement.UNKNOWN.required()).isTrue();
        assertThat(MfaRequirement.UNKNOWN.window(PLATFORM)).isEqualTo(PLATFORM);
        assertThat(MfaRequirement.UNKNOWN.allowsMethod("")).isTrue();
    }
}
