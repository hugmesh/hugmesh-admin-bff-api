package net.hugmesh.adminbff.storage;

import java.time.Instant;

/**
 * A single {@code node_storage_pool} row — ADDITIONAL storage an operator ATTACHED to one
 * mesh node so services can use SPACE on that node (schema in Liquibase
 * {@code db/changelog/085-node-storage.xml}). CLONES the
 * {@link net.hugmesh.adminbff.device.Device} record shape + idioms.
 *
 * <p>A pool is NODE-PINNED: a PV carved from it can only ever bind on {@link #deviceId()}
 * (the extended Rancher local-path-provisioner {@code nodePathMap} maps {@link #poolPath()}
 * on that node + a {@code WaitForFirstConsumer} StorageClass + explicit service
 * {@code nodeAffinity}). The pool's RESIDENCY ({@link #domain()}) + the node's
 * {@code owner_type} are read THROUGH the FK'd device — the service stamps domain from the
 * device's residency [FIX-NODEFAULT] and gates the ownership ALLOW/DENY matrix on the
 * device's {@code owner_type}.
 *
 * <ul>
 *   <li>{@code deviceId} — the node the pool is physically attached to (FK ->
 *       device_registry).</li>
 *   <li>{@code diskSerial} — a stable per-disk identity (serial/wwn); re-attaching the same
 *       disk on the same node is idempotent (at-most-one ACTIVE pool per (device, disk)).</li>
 *   <li>{@code poolPath} — the node-local path the provisioner {@code nodePathMap} maps.</li>
 *   <li>{@code reservedBytes} — the operator's capacity CLAIM. The node-agent's df is
 *       AUTHORITATIVE over this; the assign-time over-subscription check compares
 *       {@code SUM(active requested_bytes) <= reservedBytes} (and the agent verifies
 *       {@code reservedBytes <= node-df available_bytes}).</li>
 *   <li>{@code isExclusive} — one service per pool (defaulted true for video by the
 *       attach surface).</li>
 *   <li>{@code state} — {@code active} (usable) / {@code detached} (CAS audit, never
 *       deleted while history matters).</li>
 *   <li>{@code domain} — the residency brand, stamped from the device's residency, never
 *       the caller. A scoped ADMIN reads only own-brand pools.</li>
 *   <li>{@code propagationState} — the node-agent / provisioner-patch ACK the UI surfaces.</li>
 *   <li>{@code generation} — monotonic, bumped on every mutate; the per-node signed export
 *       carries {@code max(generation)} for the node's rollback guard.</li>
 * </ul>
 */
public record StoragePool(
        String id,
        String deviceId,
        String diskSerial,
        String poolPath,
        long reservedBytes,
        boolean isExclusive,
        String filesystem,
        String state,
        String domain,
        String propagationState,
        long generation,
        String createdBy,
        Instant createdAt,
        Instant detachedAt,
        String detachedBy) {

    public static final String STATE_ACTIVE = "active";
    public static final String STATE_DETACHED = "detached";

    public static final String PROP_PENDING = "pending";
    public static final String PROP_APPLIED = "applied";
    public static final String PROP_FAILED = "failed";
    public static final String PROP_DEGRADED = "degraded";

    public boolean isActive() {
        return STATE_ACTIVE.equals(state);
    }
}
