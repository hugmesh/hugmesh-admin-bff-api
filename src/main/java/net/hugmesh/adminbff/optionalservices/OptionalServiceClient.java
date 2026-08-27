package net.hugmesh.adminbff.optionalservices;

import java.util.List;

/**
 * The read/status/desired-state seam for the {@code OptionalService}
 * ({@code platform.hugmesh.net/v1alpha1}) custom resources — the desired-state objects the
 * reconciler consumes. admin-bff READS the CR spec + WRITES the CR status (the reconcile
 * loop), and — since 2026-08-26 — WRITES {@code spec.enabled} on behalf of a SUPERADMIN via
 * {@link #setEnabled} (the {@code /bff/superadmin/optional-services} surface). That is the
 * ONLY spec write and it never touches {@code spec.slug}, which the CRD's CEL rule pins
 * immutable anyway. Models the {@code cloudbackup.VeleroStatusReader} generic-resource
 * precedent EXACTLY: two implementations gated by one dark flag.
 * <ul>
 *   <li>{@code Fabric8OptionalServiceClient} — lists + status-writes + spec-writes via the
 *       fabric8 {@code KubernetesClient}, wired ONLY when
 *       {@code app.optional-services.reconcile.enabled=true};</li>
 *   <li>{@link NoopOptionalServiceClient} — the cluster-less default (flag absent /
 *       false): lists NOTHING, no-ops status writes and REFUSES spec writes
 *       ({@link OptionalServiceWriteException.Kind#NOT_WIRED}), so the reconcile contract is
 *       exercised without a cluster, the feature SHIPS DARK, and the superadmin surface
 *       cannot report a toggle it did not make.</li>
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

    /**
     * Set {@code spec.enabled} (+ the {@code reason}/{@code requestedBy} audit fields) on the
     * OptionalService CR for {@code slug}, creating the CR when the cluster carries no seed for
     * it. The ONE non-best-effort call in this package: unlike the reconcile-tick methods it
     * THROWS rather than swallowing, because a superadmin toggle that did not land must never
     * be reported as if it had.
     *
     * @param slug        the optional-service slug (== the CR name for the seed CRs)
     * @param enabled     the desired runtime state
     * @param reason      audit — why (may be null); the CRD caps this at 512 chars
     * @param requestedBy audit — the superadmin's JWT subject (may be null)
     * @return the re-projected CR as the API server accepted it
     * @throws OptionalServiceWriteException NOT_WIRED (cluster-less / dark), REJECTED (the API
     *         server refused the object, e.g. a slug outside the CRD enum) or FAILED
     */
    OptionalServiceCr setEnabled(String slug, boolean enabled, String reason, String requestedBy);

    /** True when this client actually talks to a cluster (the runtime seam signal). */
    boolean isReal();
}
