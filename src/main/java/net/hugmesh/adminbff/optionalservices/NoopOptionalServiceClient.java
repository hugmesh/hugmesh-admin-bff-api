package net.hugmesh.adminbff.optionalservices;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;

/**
 * The cluster-less default {@link OptionalServiceClient}: lists NOTHING and no-ops
 * status writes WITHOUT touching a cluster. In force whenever the real fabric8 client
 * is not enabled ({@code app.optional-services.reconcile.enabled=false}, the default) —
 * every dev / test / CI run, and the as-merged dark state. With this client in force the
 * reconciler reads an empty desired set and writes nothing, so the feature SHIPS DARK.
 *
 * <p><b>The spec write is the ONE thing this client does not no-op.</b>
 * {@link #setEnabled} THROWS {@link OptionalServiceWriteException.Kind#NOT_WIRED} instead of
 * silently succeeding, so the SUPERADMIN toggle surface answers 503 {@code dark:true} rather
 * than 200 for a write that reached no cluster. A no-op that returns success is exactly the
 * silently-inert-toggle shape this whole package now exists to make impossible.
 */
public class NoopOptionalServiceClient implements OptionalServiceClient {

    private static final Logger log = LoggerFactory.getLogger(NoopOptionalServiceClient.class);

    @Override
    public List<OptionalServiceCr> listDesired() {
        log.debug("[optional-services-reconciler] (noop) would list OptionalService CRs");
        return List.of();
    }

    @Override
    public boolean updateStatus(OptionalServiceCr cr, OptionalServiceStatus status) {
        log.debug("[optional-services-reconciler] (noop) would set status of {} -> phase={}",
                cr == null ? "?" : cr.slug(), status == null ? "?" : status.phase());
        return true;
    }

    @Override
    public OptionalServiceCr setEnabled(String slug, boolean enabled, String reason, String requestedBy) {
        log.debug("[optional-services-reconciler] (noop) REFUSING spec write for {} -> enabled={}",
                slug, enabled);
        throw new OptionalServiceWriteException(OptionalServiceWriteException.Kind.NOT_WIRED,
                "the optional-services reconciler is not wired to a cluster "
                        + "(app.optional-services.reconcile.enabled=false) — nothing was written");
    }

    @Override
    public boolean isReal() {
        return false;
    }
}
