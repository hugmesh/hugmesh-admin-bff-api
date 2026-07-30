package systems.hugmesh.adminbff.phone;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import reactor.core.publisher.Mono;

/**
 * The cluster-less default {@link PhoneLockLeg} for the Headwind device-owner DPC lock: logs
 * the would-be command and reports {@link LegOutcome#disabled} WITHOUT touching Headwind.
 * Wired whenever the real leg is not enabled ({@code app.phone-lock.headwind.enabled=false},
 * the default) — CI, dev, every deployment that has not provisioned the Headwind REST custody.
 *
 * <p>Mirrors {@link systems.hugmesh.adminbff.device.NoopHeadscalePolicyClient}: the
 * aggregate enforcement contract runs identically, only the actual DPC command is a no-op,
 * so the whole {@link PhoneLockEnforcer} degrade path is exercised with no live Headwind.
 */
public class NoopHeadwindDpcLockClient implements PhoneLockLeg {

    private static final Logger log = LoggerFactory.getLogger(NoopHeadwindDpcLockClient.class);

    static final String LEG = "headwind-dpc";

    @Override
    public String name() {
        return LEG;
    }

    /** Provider-matched exactly like the real Headwind leg, so a Headwind device selects THIS
     *  no-op (and degrades) while an Azure device does not, keeping the fan-out symmetric. */
    @Override
    public boolean appliesTo(PhoneDevice device) {
        return PhoneDevice.MDM_PROVIDER_HEADWIND.equals(device.effectiveMdmProvider());
    }

    @Override
    public Mono<LegOutcome> lock(PhoneDevice device) {
        return disabled("lock");
    }

    @Override
    public Mono<LegOutcome> unlock(PhoneDevice device) {
        return disabled("unlock");
    }

    private Mono<LegOutcome> disabled(String verb) {
        log.debug("[phone-lock] (noop) would {} device-owner DPC — headwind leg disabled, no push", verb);
        return Mono.just(LegOutcome.disabled("headwind DPC leg disabled (app.phone-lock.headwind.enabled=false)"));
    }
}
