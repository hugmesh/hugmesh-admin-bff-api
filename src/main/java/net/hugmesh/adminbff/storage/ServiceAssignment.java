package net.hugmesh.adminbff.storage;

import java.time.Instant;

/**
 * A single {@code storage_service_assignment} row — the explicit (pool x service) placement
 * (schema in Liquibase {@code db/changelog/085-node-storage.xml}). An ACTIVE row pins
 * {@link #serviceName()} to the pool's node (nodeAffinity + a node-pinned local PV the
 * {@link #pvcName()} binds). CLONES the
 * {@link net.hugmesh.adminbff.device.SshLicense} record idioms.
 *
 * <p>It is the audit trail: a retire is a CAS {@code active -> revoked} (the row is NEVER
 * deleted), and every mutate bumps {@code generation} so the signed export's monotonic
 * rollback guard can reject a replayed (lower-generation) payload. An ACTIVE row is the
 * single element the {@code apps/13b} ApplicationSet list-generator selects on
 * ({@code selector state:active}).
 *
 * <ul>
 *   <li>{@code poolId} — the pool whose node-local space this consumes (FK -> pool). The
 *       assignment's residency is read THROUGH this FK.</li>
 *   <li>{@code serviceName} — the workload being placed; the Kustomize patch keys on it.</li>
 *   <li>{@code pvcName} — the PVC the patch binds to the node-pinned PV.</li>
 *   <li>{@code requestedBytes} — the slice of the pool reserved for this service; the
 *       assign-time over-subscription check rejects {@code SUM > pool.reservedBytes}.</li>
 *   <li>{@code state} — {@code active} (placed) / {@code revoked} (CAS, audited).</li>
 *   <li>{@code domain} — stamped from the pool's residency, never the caller
 *       [FIX-NODEFAULT].</li>
 *   <li>{@code propagationState} — the GitOps placement / rebalance ACK the UI surfaces.</li>
 *   <li>{@code generation} — monotonic, bumped on every mutate.</li>
 * </ul>
 */
public record ServiceAssignment(
        String id,
        String poolId,
        String serviceName,
        String pvcName,
        long requestedBytes,
        String state,
        String assignedBy,
        Instant assignedAt,
        Instant revokedAt,
        String revokedBy,
        String domain,
        String propagationState,
        long generation) {

    public static final String STATE_ACTIVE = "active";
    public static final String STATE_REVOKED = "revoked";

    public static final String PROP_PENDING = "pending";
    public static final String PROP_APPLIED = "applied";
    public static final String PROP_FAILED = "failed";
    public static final String PROP_DEGRADED = "degraded";

    public boolean isActive() {
        return STATE_ACTIVE.equals(state);
    }
}
