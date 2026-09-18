package net.hugmesh.adminbff.backingservices;

import reactor.core.publisher.Mono;

/**
 * The seam to the real MANAGED-MODE effector — the future leg that converges the cluster to a
 * recorded {@link BackingServiceMode}: prune the in-mesh workload Application + manifests, keep
 * the same ESO Secret names sourcing operator-supplied managed creds, and re-point the
 * consumers' endpoint env (BOTH the R2DBC and Liquibase URLs for a DB) at the managed endpoint —
 * mirroring the generator's image-time {@code gate_backing_services()} but at runtime.
 *
 * <p><b>SHIPS DARK, but no longer DEFERRED.</b> The DEFAULT is still
 * {@link NoopBackingServiceEffector}, which does NOTHING but log — a recorded managed mode sits
 * as durable INTENT and NO cluster write happens. The real implementation now exists:
 * {@link Fabric8BackingServiceEffector}, selected by
 * {@code app.backing-services.effector.enabled=true}. It re-points the endpoint indirection
 * (the per-namespace {@code backing-service-endpoints} ConfigMap) and performs a TARGETED
 * ROLLING RESTART of that service's consumers — never a live re-dial, which
 * {@code configMapKeyRef} cannot do.
 *
 * <p>What is STILL deferred, and why the flag stays off by default: the parity blockers this
 * axis has always carried — TLS/truststore deltas, the out-of-band role-split SQL, Citus
 * incompatibility, the tier-3 services with no clean managed analog — plus the consumer-side
 * conversion from a literal env {@code value:} to a {@code configMapKeyRef}, without which the
 * ConfigMap this effector writes is read by nobody. Pruning the in-mesh workload stays out of
 * scope entirely (an ArgoCD-owned Application; deleting it at runtime is selfHealed back).
 */
public interface BackingServiceEffector {

    /**
     * Converge the cluster toward the recorded desired mode for one backing service. The default
     * Noop is dark (logs + returns). The real effector prunes/re-points as described above.
     */
    Mono<Void> applyMode(BackingServiceMode desired);

    /** True iff a REAL effector is wired (false for the Noop) — for honest reconcile logging. */
    boolean isReal();
}
