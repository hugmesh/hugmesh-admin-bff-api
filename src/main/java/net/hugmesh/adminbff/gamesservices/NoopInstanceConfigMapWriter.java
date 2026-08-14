package net.hugmesh.adminbff.gamesservices;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import reactor.core.publisher.Mono;

import java.util.List;

/**
 * The cluster-less default {@link InstanceConfigMapWriter}: logs the would-be render and
 * reports success WITHOUT touching a cluster. Used whenever the real fabric8 writer is not
 * enabled ({@code games-services.reconciler.enabled=false}, the default) — a single-replica
 * / dev / test / CI run. The reconcile contract (CAS state transitions + propagation_state
 * forward-reconcile) is fully exercised; only the actual ConfigMap apply is a no-op.
 */
public class NoopInstanceConfigMapWriter implements InstanceConfigMapWriter {

    private static final Logger log = LoggerFactory.getLogger(NoopInstanceConfigMapWriter.class);

    @Override
    public Mono<Boolean> writeDomainConfigMap(String domain, List<GameInstance> instances) {
        log.debug("[games-reconciler] (noop) would render {} active instance(s) into "
                + "domain '{}' ConfigMap", instances == null ? 0 : instances.size(), domain);
        return Mono.just(true);
    }

    @Override
    public boolean isReal() {
        return false;
    }
}
