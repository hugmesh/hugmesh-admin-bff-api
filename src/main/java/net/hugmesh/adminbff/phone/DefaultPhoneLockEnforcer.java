package net.hugmesh.adminbff.phone;

import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.util.List;
import java.util.function.BiFunction;
import java.util.stream.Collectors;

/**
 * The aggregating {@link PhoneLockEnforcer}: injects EVERY {@link PhoneLockLeg} bean (exactly
 * one per leg — the real client when its flag is on, else the no-op — see
 * {@link PhoneLockConfig}) and reduces their outcomes.
 *
 * <p>Reduction (both a lock and an unlock use it identically):
 * <ul>
 *   <li>any enabled leg hard-rejected (FAILED) &rarr; {@code FAILED};</li>
 *   <li>else any leg disabled OR any enabled leg unreachable &rarr; {@code DEGRADED}
 *       (both-off default &rarr; the documented Headwind-console reason);</li>
 *   <li>else (every leg enabled and applied) &rarr; {@code APPLIED}.</li>
 * </ul>
 * Every leg call is additionally wrapped so a leg that forgot its own fail-closed contract
 * still cannot throw the aggregate — a bug in a leg degrades to FAILED, never a 500 on the
 * mutation (the lock row is already authoritative).
 */
@Service
@SuppressFBWarnings(value = "EI_EXPOSE_REP2",
        justification = "Spring constructor injection: the container owns this singleton collaborator and it is never mutated by this class after construction; a defensive copy of a bean is meaningless (not caller-owned mutable data).")
public class DefaultPhoneLockEnforcer implements PhoneLockEnforcer {

    private static final Logger log = LoggerFactory.getLogger(DefaultPhoneLockEnforcer.class);

    /** The documented DEGRADED reason when NO enforcement channel is enabled (the default). */
    static final String ALL_DISABLED_REASON =
            "enforcement channels disabled; issue the lock via the Headwind /manage console";

    private final List<PhoneLockLeg> legs;

    public DefaultPhoneLockEnforcer(List<PhoneLockLeg> legs) {
        this.legs = legs;
    }

    @Override
    public Mono<Outcome> enforceLock(PhoneDevice device) {
        return aggregate(device, PhoneLockLeg::lock);
    }

    @Override
    public Mono<Outcome> enforceUnlock(PhoneDevice device) {
        return aggregate(device, PhoneLockLeg::unlock);
    }

    /**
     * Run {@code op} on the legs that APPLY to this device (fail-closed per leg), collect, then
     * reduce. A DPC leg applies only for the device's reported provider ({@code HeadwindDpcLockClient}
     * for a headwind/null-provider device, {@code AzureIntuneLockClient} for an azure-intune
     * device); the provider-independent mesh-deny leg applies to every device. Filtering here
     * keeps the reduce identical — the non-matching provider's leg simply never contributes an
     * outcome, so a headwind device's aggregate is unchanged by the presence of the Azure leg.
     */
    private Mono<Outcome> aggregate(PhoneDevice device,
                                    BiFunction<PhoneLockLeg, PhoneDevice, Mono<PhoneLockLeg.LegOutcome>> op) {
        return Flux.fromIterable(legs)
                .filter(leg -> leg.appliesTo(device))
                // Mono.defer so a leg that throws SYNCHRONOUSLY (before returning its Mono) is
                // captured into the reactive chain and hits onErrorResume below — otherwise a
                // synchronous throw would escape flatMap and error the whole aggregate.
                .flatMap(leg -> Mono.defer(() -> op.apply(leg, device))
                        // Defence-in-depth: a leg MUST NOT throw, but if one does — reactively
                        // OR synchronously — its bug degrades to a FAILED leg, never an errored
                        // aggregate (the control-plane lock row is already authoritative).
                        .onErrorResume(e -> Mono.just(PhoneLockLeg.LegOutcome.failed(
                                "leg '" + leg.name() + "' threw: " + e)))
                        .map(o -> new NamedOutcome(leg.name(), o)))
                .collectList()
                .map(this::reduce);
    }

    private Outcome reduce(List<NamedOutcome> outcomes) {
        if (outcomes.isEmpty()) {
            // No leg bean at all (should not happen — the config always wires one per leg).
            return Outcome.degraded(ALL_DISABLED_REASON);
        }
        String failed = join(outcomes, PhoneLockLeg.LegOutcome::isFailed);
        if (!failed.isEmpty()) {
            log.warn("[phone-lock] enforcement FAILED: {}", failed);
            return Outcome.failed(failed);
        }
        long disabled = outcomes.stream().filter(n -> n.outcome().isDisabled()).count();
        if (disabled == outcomes.size()) {
            // Every channel off — the default shipping posture. The documented console hint.
            return Outcome.degraded(ALL_DISABLED_REASON);
        }
        boolean anyDisabled = disabled > 0;
        boolean anyUnreachable = outcomes.stream().anyMatch(n -> n.outcome().isUnreachable());
        if (anyDisabled || anyUnreachable) {
            String reason = describe(outcomes);
            log.info("[phone-lock] enforcement DEGRADED: {}", reason);
            return Outcome.degraded(reason);
        }
        return Outcome.applied();
    }

    /** Comma-joined "leg: detail" for the legs matching {@code pred} (empty when none). */
    private static String join(List<NamedOutcome> outcomes,
                               java.util.function.Predicate<PhoneLockLeg.LegOutcome> pred) {
        return outcomes.stream()
                .filter(n -> pred.test(n.outcome()))
                .map(n -> n.name() + ": " + n.outcome().detail())
                .collect(Collectors.joining("; "));
    }

    /** A short per-leg status line for the DEGRADED reason. */
    private static String describe(List<NamedOutcome> outcomes) {
        return outcomes.stream()
                .map(n -> n.name() + "=" + n.outcome().result().name().toLowerCase(java.util.Locale.ROOT))
                .collect(Collectors.joining(", "));
    }

    private record NamedOutcome(String name, PhoneLockLeg.LegOutcome outcome) {
    }
}
