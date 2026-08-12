package net.hugmesh.adminbff.backingservices;

import reactor.core.publisher.Mono;

/**
 * The seam to the real MANAGED-MODE effector — the future leg that converges the cluster to a
 * recorded {@link BackingServiceMode}: prune the in-mesh workload Application + manifests, keep
 * the same ESO Secret names sourcing operator-supplied managed creds, and re-point the
 * consumers' endpoint env (BOTH the R2DBC and Liquibase URLs for a DB) at the managed endpoint —
 * mirroring the generator's image-time {@code gate_backing_services()} but at runtime.
 *
 * <p><b>SHIPS DARK / DEFERRED.</b> The v1 default is {@link NoopBackingServiceEffector}, which
 * does NOTHING but log — a recorded managed mode sits as durable INTENT and NO cluster write
 * happens. The live flip lever is deliberately deferred: managed backing-service swaps carry
 * real parity blockers (TLS/truststore deltas, out-of-band role-split SQL, Citus incompatibility,
 * and the tier-3 services that have no clean managed analog at all), so v1 records intent + emits
 * honest docs/checklists rather than pretend to re-point production datastores. A follow-on leg
 * supplies the real effector behind this interface (the {@code VeleroBackupEffector} /
 * {@code Fabric8OptionalServiceApplicationSetPatcher} shape), gated on its own ships-dark flag.
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
