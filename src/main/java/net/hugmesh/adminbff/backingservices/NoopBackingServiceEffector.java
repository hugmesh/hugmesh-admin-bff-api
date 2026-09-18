package net.hugmesh.adminbff.backingservices;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import reactor.core.publisher.Mono;

/**
 * The DEFAULT, DARK {@link BackingServiceEffector}. While
 * {@code app.backing-services.effector.enabled} is false — the default, and every deployment
 * until an operator turns it on — {@link #applyMode} does NOTHING but log: the
 * {@code backing_service_mode} ledger row is written by the service, but NO ConfigMap write and
 * NO consumer restart happens, so the feature records durable INTENT and ships dark exactly like
 * {@code NoopBackupEffector} and the optional-services Noop seams.
 *
 * <p>{@link BackingServiceEffectorConfig} selects this or the real
 * {@link Fabric8BackingServiceEffector} by that one property, with mutually-exclusive
 * conditions, so exactly one is registered in every mode.
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
