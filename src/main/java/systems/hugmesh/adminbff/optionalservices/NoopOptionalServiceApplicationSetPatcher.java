package systems.hugmesh.adminbff.optionalservices;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Map;

/**
 * The cluster-less default {@link OptionalServiceApplicationSetPatcher}: logs the would-be
 * element flips and reports success WITHOUT touching the {@code optional-services}
 * ApplicationSet. In force whenever the real fabric8 patcher is not enabled
 * ({@code app.optional-services.reconcile.enabled=false}, the default), so the feature
 * SHIPS DARK — 13a stays at its git baseline and no Application is created/pruned.
 */
public class NoopOptionalServiceApplicationSetPatcher implements OptionalServiceApplicationSetPatcher {

    private static final Logger log =
            LoggerFactory.getLogger(NoopOptionalServiceApplicationSetPatcher.class);

    @Override
    public boolean apply(Map<String, Boolean> desired) {
        log.debug("[optional-services-reconciler] (noop) would reconcile {} ApplicationSet element(s)",
                desired == null ? 0 : desired.size());
        return true;
    }

    @Override
    public boolean isReal() {
        return false;
    }
}
