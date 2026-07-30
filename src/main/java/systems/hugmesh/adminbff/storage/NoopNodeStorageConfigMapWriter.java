package systems.hugmesh.adminbff.storage;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;

/**
 * The cluster-less default {@link NodeStorageConfigMapWriter}: logs the would-be render and
 * reports success WITHOUT touching a cluster. In force whenever the real fabric8 writer is not
 * enabled ({@code node-storage.reconciler.enabled=false}, the default) — a single-replica /
 * dev / test / CI run, AND the as-merged inert state.
 *
 * <p>The reconcile contract (read active rows -> render elements -> forward-reconcile each
 * row's {@code propagation_state}) is fully exercised; only the actual ConfigMap apply is a
 * no-op. This is why the feature SHIPS DARK: with this writer in force nothing is written to
 * the cluster, so the {@code node-storage-assignments} ConfigMap stays whatever it is today
 * (empty / absent => 13b generates zero placements).
 */
public class NoopNodeStorageConfigMapWriter implements NodeStorageConfigMapWriter {

    private static final Logger log = LoggerFactory.getLogger(NoopNodeStorageConfigMapWriter.class);

    @Override
    public boolean writeAssignments(List<StorageAssignmentElement> elements) {
        log.debug("[node-storage-reconciler] (noop) would render {} active assignment element(s) "
                + "into the node-storage-assignments ConfigMap",
                elements == null ? 0 : elements.size());
        return true;
    }

    @Override
    public boolean isReal() {
        return false;
    }
}
