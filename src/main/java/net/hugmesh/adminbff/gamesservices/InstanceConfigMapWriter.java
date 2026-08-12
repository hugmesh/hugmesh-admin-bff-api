package net.hugmesh.adminbff.gamesservices;

import java.util.List;

/**
 * The seam that writes the per-domain ACTIVE-instance ConfigMap that the generator's
 * games-instances ApplicationSet (apps/13c, PR5) reads to render per-instance
 * Deployment/Service/PVC. admin-bff is the SINGLE writer of these ConfigMaps; ArgoCD is
 * apply-only — the Lease + {@code propagation_state} are the SOLE coordination, or
 * instances flap.
 *
 * <p>Two implementations (the {@code JobLauncher} precedent):
 * <ul>
 *   <li>{@link Fabric8InstanceConfigMapWriter} — patches the ConfigMap with the fabric8
 *       {@code KubernetesClient}, gated by {@code games-services.reconciler.enabled=true};</li>
 *   <li>{@link NoopInstanceConfigMapWriter} — the cluster-less default for dev/test/CI, so
 *       the reconcile contract (CAS + propagation_state) is fully exercisable without a
 *       live cluster.</li>
 * </ul>
 */
public interface InstanceConfigMapWriter {

    /**
     * Render the given domain's ACTIVE instances into its per-domain ConfigMap (replacing
     * the previous contents — the ConfigMap is the desired set, so a removed instance
     * disappears). Returns true on a successful apply.
     *
     * @param domain    the brand/tenant whose ConfigMap is being written
     * @param instances the domain's current ACTIVE instances (may be empty -> empty ConfigMap)
     */
    boolean writeDomainConfigMap(String domain, List<GameInstance> instances);

    /** True when this writer actually talks to a cluster (the runtime seam signal). */
    boolean isReal();
}
