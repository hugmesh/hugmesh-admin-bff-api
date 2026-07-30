package systems.hugmesh.adminbff.backingservices;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import reactor.core.publisher.Mono;

/**
 * The DEFAULT, DARK {@link BackingServiceEffector}. With no real managed-mode effector wired
 * (the v1 default AND every deployment until the generator/effector leg ships the real one),
 * {@link #applyMode} does NOTHING but log — the {@code backing_service_mode} ledger row is
 * written by the service, but NO cluster prune / endpoint re-point happens, so the feature
 * records durable INTENT and ships dark exactly like {@code NoopBackupEffector} and the
 * optional-services Noop seams.
 *
 * <p>Registered as an {@code @ConditionalOnMissingBean} default by
 * {@link BackingServiceEffectorConfig}, so a follow-on leg's real effector (defined elsewhere)
 * deterministically replaces it without touching this class.
 */
public class NoopBackingServiceEffector implements BackingServiceEffector {

    private static final Logger log = LoggerFactory.getLogger(NoopBackingServiceEffector.class);

    @Override
    public Mono<Void> applyMode(BackingServiceMode desired) {
        log.info("[backing-services] SHIPS DARK — no managed-mode effector wired; recorded "
                        + "intent service={} mode={} endpoint={} stays intent-only (no cluster "
                        + "prune / endpoint re-point emitted)",
                desired.serviceId(), desired.mode(),
                desired.endpoint() == null ? "-" : desired.endpoint());
        return Mono.empty();
    }

    @Override
    public boolean isReal() {
        return false;
    }
}
