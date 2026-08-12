package net.hugmesh.adminbff.optionalservices;

import java.util.List;

/**
 * The read/status seam for the {@code OptionalService}
 * ({@code platform.hugmesh.systems/v1alpha1}) custom resources — the desired-state
 * objects the reconciler consumes. admin-bff READS the CR spec + WRITES the CR status;
 * it never writes the CR spec (that is the admin/superadmin or the follow-on BFF
 * endpoint). Models the {@code cloudbackup.VeleroStatusReader} generic-resource
 * precedent EXACTLY: two implementations gated by one dark flag.
 * <ul>
 *   <li>{@code Fabric8OptionalServiceClient} — lists + status-writes via the fabric8
 *       {@code KubernetesClient}, wired ONLY when
 *       {@code app.optional-services.reconcile.enabled=true};</li>
 *   <li>{@link NoopOptionalServiceClient} — the cluster-less default (flag absent /
 *       false): lists NOTHING and no-ops status writes, so the reconcile contract is
 *       exercised without a cluster and the feature SHIPS DARK.</li>
 * </ul>
 */
public interface OptionalServiceClient {

    /** Every OptionalService CR in the operator namespace, projected fabric8-free. Empty when none / cluster-less. */
    List<OptionalServiceCr> listDesired();

    /**
     * Write the computed status onto ONE CR's {@code /status} subresource. Best-effort:
     * returns {@code false} (swallowing the error) on any failure so the reconcile tick
     * never dies — the status is re-computed next tick.
     */
    boolean updateStatus(OptionalServiceCr cr, OptionalServiceStatus status);

    /** True when this client actually talks to a cluster (the runtime seam signal). */
    boolean isReal();
}
