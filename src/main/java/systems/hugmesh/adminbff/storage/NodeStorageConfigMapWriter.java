package systems.hugmesh.adminbff.storage;

import java.util.List;

/**
 * The seam that writes the SINGLE {@code node-storage-assignments} ConfigMap the generator's
 * node-storage ApplicationSet ({@code apps/13b-node-storage.yaml}) reads to render one
 * placement Application per ACTIVE assignment (nodeAffinity + node-pinned PVC). admin-bff is
 * the SINGLE writer of this ConfigMap; ArgoCD is apply-only — the Lease + each row's
 * {@code propagation_state} are the SOLE coordination, or placements flap.
 *
 * <p>Models the games {@link InstanceConfigMapWriter} / test-reports {@code JobLauncher}
 * precedent EXACTLY — two implementations gated by a single dark flag:
 * <ul>
 *   <li>{@code Fabric8NodeStorageConfigMapWriter} — server-side-applies the ConfigMap with the
 *       fabric8 {@code KubernetesClient}, wired ONLY when
 *       {@code node-storage.reconciler.enabled=true};</li>
 *   <li>{@link NoopNodeStorageConfigMapWriter} — the cluster-less default (the flag is absent /
 *       false) so the reconcile contract (render + {@code propagation_state} forward-reconcile)
 *       is fully exercisable without a live cluster, and the feature SHIPS DARK.</li>
 * </ul>
 *
 * <p>Unlike the games per-domain ConfigMaps, 13b consumes ONE global list (every brand's
 * active assignments in a single list-generator), so this writer takes the full element set and
 * replaces the ConfigMap as the desired set: an absent (revoked / never-assigned) element
 * simply disappears, and ArgoCD's {@code prune:true} unplaces it.
 */
public interface NodeStorageConfigMapWriter {

    /**
     * Render the given ACTIVE assignment elements into the {@code node-storage-assignments}
     * ConfigMap (replacing the previous contents — the ConfigMap IS the desired set). An EMPTY
     * list yields an EMPTY ConfigMap (the inert default: zero placements, today's behaviour).
     * Returns true on a successful apply.
     *
     * @param elements the current ACTIVE assignment elements (may be empty -> empty ConfigMap)
     */
    boolean writeAssignments(List<StorageAssignmentElement> elements);

    /** True when this writer actually talks to a cluster (the runtime seam signal). */
    boolean isReal();
}
