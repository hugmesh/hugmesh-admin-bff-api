package systems.hugmesh.adminbff.phone;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import reactor.core.publisher.Mono;

/**
 * The cluster-less default {@link PhoneLockLeg} for the Azure Intune (Graph) device lock: logs
 * the would-be command and reports {@link LegOutcome#disabled} WITHOUT touching Microsoft Graph.
 * Wired whenever the real leg is not enabled ({@code app.phone-lock.azure-intune.enabled=false},
 * the DEFAULT — Intune ships dark so a deployment stays sovereign until it explicitly opts in).
 *
 * <p>Mirrors {@link NoopHeadwindDpcLockClient}: the aggregate enforcement contract runs
 * identically, only the actual Graph call is a no-op. Like the real Azure leg it is
 * provider-matched — it selects ONLY for an {@code 'azure-intune'} device — so the fan-out
 * stays symmetric (a Headwind device never touches this leg, and an Azure device with the flag
 * off degrades cleanly with no live Graph).
 */
public class NoopAzureIntuneLockClient implements PhoneLockLeg {

    private static final Logger log = LoggerFactory.getLogger(NoopAzureIntuneLockClient.class);

    static final String LEG = "azure-intune";

    @Override
    public String name() {
        return LEG;
    }

    /** Provider-matched exactly like the real Intune leg (only an 'azure-intune' device). */
    @Override
    public boolean appliesTo(PhoneDevice device) {
        return PhoneDevice.MDM_PROVIDER_AZURE_INTUNE.equals(device.effectiveMdmProvider());
    }

    @Override
    public Mono<LegOutcome> lock(PhoneDevice device) {
        return disabled("remote-lock");
    }

    @Override
    public Mono<LegOutcome> unlock(PhoneDevice device) {
        return disabled("clear-lock");
    }

    private Mono<LegOutcome> disabled(String verb) {
        log.debug("[phone-lock] (noop) would {} via Intune/Graph — azure-intune leg disabled, no push",
                verb);
        return Mono.just(LegOutcome.disabled(
                "azure-intune leg disabled (app.phone-lock.azure-intune.enabled=false)"));
    }
}
