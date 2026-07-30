package systems.hugmesh.adminbff.phone;

import org.junit.jupiter.api.Test;
import reactor.core.publisher.Mono;

import java.time.Instant;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The {@link DefaultPhoneLockEnforcer} aggregation matrix — the reduce rule that turns the
 * per-leg outcomes into ONE propagation state, proven with hand-built legs (no Spring):
 * <ul>
 *   <li>both legs off (the default no-op pair) &rarr; DEGRADED + the documented console reason;</li>
 *   <li>one applied + one disabled &rarr; DEGRADED;</li>
 *   <li>every enabled leg applied &rarr; APPLIED;</li>
 *   <li>an enabled leg's channel rejected (FAILED) &rarr; FAILED (wins over degraded);</li>
 *   <li>an enabled leg unreachable + one applied &rarr; DEGRADED;</li>
 *   <li>a leg that THROWS is contained &rarr; FAILED, never an errored aggregate.</li>
 * </ul>
 */
class PhoneLockEnforcerTest {

    private static final PhoneDevice DEVICE = new PhoneDevice("pd", "phone-x", "phone", null,
            "oriole", null, null, null, null, null, null, "phone-host", null, null, false,
            null, null, false, null, null, null, null, null, null, null, null, null,
            Instant.now(), Instant.now(), 1L, "mesh_owned", "locked", "pending", 1L,
            "r", "sa", Instant.now(), null, null, "headwind", null);

    /** A fixed-result leg. */
    private static PhoneLockLeg leg(String name, PhoneLockLeg.LegOutcome outcome) {
        return new PhoneLockLeg() {
            public String name() { return name; }
            public Mono<LegOutcome> lock(PhoneDevice d) { return Mono.just(outcome); }
            public Mono<LegOutcome> unlock(PhoneDevice d) { return Mono.just(outcome); }
        };
    }

    private static PhoneLockEnforcer.Outcome enforceLock(PhoneLockLeg... legs) {
        return new DefaultPhoneLockEnforcer(List.of(legs)).enforceLock(DEVICE).block();
    }

    @Test
    void bothLegsOff_default_degradedWithDocumentedReason() {
        PhoneLockEnforcer.Outcome o = enforceLock(
                new NoopHeadwindDpcLockClient(), new NoopPhoneMeshDenyClient());
        assertThat(o.isDegraded()).isTrue();
        assertThat(o.propagationState()).isEqualTo("degraded");
        assertThat(o.reason()).isEqualTo(DefaultPhoneLockEnforcer.ALL_DISABLED_REASON);
    }

    @Test
    void oneAppliedOneDisabled_degraded() {
        PhoneLockEnforcer.Outcome o = enforceLock(
                leg("headwind-dpc", PhoneLockLeg.LegOutcome.applied()),
                new NoopPhoneMeshDenyClient());
        assertThat(o.isDegraded()).isTrue();
    }

    @Test
    void allEnabledApplied_applied() {
        PhoneLockEnforcer.Outcome o = enforceLock(
                leg("headwind-dpc", PhoneLockLeg.LegOutcome.applied()),
                leg("mesh-deny", PhoneLockLeg.LegOutcome.applied()));
        assertThat(o.isApplied()).isTrue();
        assertThat(o.propagationState()).isEqualTo("applied");
    }

    @Test
    void anEnabledLegRejected_failed_winsOverDegraded() {
        PhoneLockEnforcer.Outcome o = enforceLock(
                leg("headwind-dpc", PhoneLockLeg.LegOutcome.failed("HTTP 500")),
                new NoopPhoneMeshDenyClient());
        assertThat(o.isFailed()).isTrue();
        assertThat(o.propagationState()).isEqualTo("failed");
        assertThat(o.reason()).contains("headwind-dpc");
    }

    @Test
    void enabledUnreachablePlusApplied_degraded() {
        PhoneLockEnforcer.Outcome o = enforceLock(
                leg("headwind-dpc", PhoneLockLeg.LegOutcome.applied()),
                leg("mesh-deny", PhoneLockLeg.LegOutcome.unreachable("timeout")));
        assertThat(o.isDegraded()).isTrue();
    }

    // ── provider-aware fan-out (changeset 307) ───────────────────────────────────

    private static PhoneDevice deviceWithProvider(String provider) {
        return new PhoneDevice("pd", "phone-x", "phone", null, "oriole", null, null, null, null,
                null, null, "phone-host", null, null, false, null, null, false, null, null,
                null, null, null, null, null, null, null, Instant.now(), Instant.now(), 1L,
                "mesh_owned", "locked", "pending", 1L, "r", "sa", Instant.now(), null, null,
                provider, provider == null ? null : "intune-id");
    }

    /** A leg that counts its lock/unlock invocations and matches a given provider (null = the
     *  provider-independent mesh-deny leg that always applies). */
    static final class CountingLeg implements PhoneLockLeg {
        final String name;
        final String matchProvider;
        int lockCalls;
        int unlockCalls;

        CountingLeg(String name, String matchProvider) {
            this.name = name;
            this.matchProvider = matchProvider;
        }

        @Override public String name() { return name; }

        @Override public boolean appliesTo(PhoneDevice d) {
            return matchProvider == null || matchProvider.equals(d.effectiveMdmProvider());
        }

        @Override public Mono<LegOutcome> lock(PhoneDevice d) {
            lockCalls++;
            return Mono.just(LegOutcome.applied());
        }

        @Override public Mono<LegOutcome> unlock(PhoneDevice d) {
            unlockCalls++;
            return Mono.just(LegOutcome.applied());
        }
    }

    @Test
    void headwindDevice_fansToHeadwindDpcAndMeshDeny_notAzure() {
        CountingLeg hw = new CountingLeg("headwind-dpc", "headwind");
        CountingLeg az = new CountingLeg("azure-intune", "azure-intune");
        CountingLeg mesh = new CountingLeg("mesh-deny", null);
        DefaultPhoneLockEnforcer enf = new DefaultPhoneLockEnforcer(List.of(hw, az, mesh));

        PhoneLockEnforcer.Outcome o = enf.enforceLock(deviceWithProvider("headwind")).block();
        assertThat(o.isApplied()).isTrue();
        assertThat(hw.lockCalls).isEqualTo(1);      // the matching DPC leg fired
        assertThat(mesh.lockCalls).isEqualTo(1);    // mesh-deny always fires
        assertThat(az.lockCalls).isZero();          // the Azure leg was NOT invoked
    }

    @Test
    void nullProviderDevice_treatedAsHeadwind() {
        CountingLeg hw = new CountingLeg("headwind-dpc", "headwind");
        CountingLeg az = new CountingLeg("azure-intune", "azure-intune");
        CountingLeg mesh = new CountingLeg("mesh-deny", null);
        DefaultPhoneLockEnforcer enf = new DefaultPhoneLockEnforcer(List.of(hw, az, mesh));

        enf.enforceLock(deviceWithProvider(null)).block();   // null provider folds to headwind
        assertThat(hw.lockCalls).isEqualTo(1);
        assertThat(az.lockCalls).isZero();
        assertThat(mesh.lockCalls).isEqualTo(1);
    }

    @Test
    void azureDevice_fansToAzureDpcAndMeshDeny_notHeadwind() {
        CountingLeg hw = new CountingLeg("headwind-dpc", "headwind");
        CountingLeg az = new CountingLeg("azure-intune", "azure-intune");
        CountingLeg mesh = new CountingLeg("mesh-deny", null);
        DefaultPhoneLockEnforcer enf = new DefaultPhoneLockEnforcer(List.of(hw, az, mesh));

        PhoneLockEnforcer.Outcome o = enf.enforceLock(deviceWithProvider("azure-intune")).block();
        assertThat(o.isApplied()).isTrue();
        assertThat(az.lockCalls).isEqualTo(1);      // the matching DPC leg fired
        assertThat(mesh.lockCalls).isEqualTo(1);    // mesh-deny always fires
        assertThat(hw.lockCalls).isZero();          // the Headwind leg was NOT invoked
    }

    @Test
    void unlock_fansToMatchingProviderLegOnly() {
        CountingLeg hw = new CountingLeg("headwind-dpc", "headwind");
        CountingLeg az = new CountingLeg("azure-intune", "azure-intune");
        CountingLeg mesh = new CountingLeg("mesh-deny", null);
        DefaultPhoneLockEnforcer enf = new DefaultPhoneLockEnforcer(List.of(hw, az, mesh));

        enf.enforceUnlock(deviceWithProvider("azure-intune")).block();
        assertThat(az.unlockCalls).isEqualTo(1);
        assertThat(mesh.unlockCalls).isEqualTo(1);
        assertThat(hw.unlockCalls).isZero();
    }

    @Test
    void aThrowingLeg_isContainedAsFailed() {
        PhoneLockLeg boom = new PhoneLockLeg() {
            public String name() { return "boom"; }
            public Mono<LegOutcome> lock(PhoneDevice d) { return Mono.error(new IllegalStateException("kaboom")); }
            public Mono<LegOutcome> unlock(PhoneDevice d) { return Mono.error(new IllegalStateException("kaboom")); }
        };
        PhoneLockEnforcer.Outcome o = enforceLock(boom, new NoopPhoneMeshDenyClient());
        assertThat(o.isFailed()).isTrue();                       // never throws the aggregate
        assertThat(o.reason()).contains("boom");
    }

    @Test
    void aSynchronouslyThrowingLeg_isContainedAsFailed() {
        // A leg that throws SYNCHRONOUSLY from lock()/unlock() (before returning its Mono) must
        // STILL be contained as FAILED rather than erroring the aggregate — the enforcer's
        // Mono.defer captures the synchronous throw into the reactive chain. Without defer this
        // would escape flatMap and 500 the mutation despite the lock row being authoritative.
        PhoneLockLeg boomSync = new PhoneLockLeg() {
            public String name() { return "boom-sync"; }
            public Mono<LegOutcome> lock(PhoneDevice d) { throw new IllegalStateException("kaboom-sync"); }
            public Mono<LegOutcome> unlock(PhoneDevice d) { throw new IllegalStateException("kaboom-sync"); }
        };
        PhoneLockEnforcer.Outcome o = enforceLock(boomSync, new NoopPhoneMeshDenyClient());
        assertThat(o.isFailed()).isTrue();                       // never throws the aggregate
        assertThat(o.reason()).contains("boom-sync");
    }
}
