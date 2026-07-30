package systems.hugmesh.adminbff.optionalservices;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Map;

/**
 * The cluster-less default {@link InstalledServicesConfigMapWriter}: logs the would-be
 * boolean flips and reports success WITHOUT touching the {@code installed-services}
 * ConfigMap. In force whenever the real fabric8 writer is not enabled
 * ({@code app.optional-services.reconcile.enabled=false}, the default), so the feature
 * SHIPS DARK — the greying booleans stay whatever the build rendered.
 */
public class NoopInstalledServicesConfigMapWriter implements InstalledServicesConfigMapWriter {

    private static final Logger log =
            LoggerFactory.getLogger(NoopInstalledServicesConfigMapWriter.class);

    @Override
    public boolean mirror(Map<String, Boolean> desired) {
        log.debug("[optional-services-reconciler] (noop) would mirror {} installed-services boolean(s)",
                desired == null ? 0 : desired.size());
        return true;
    }

    @Override
    public boolean isReal() {
        return false;
    }
}
