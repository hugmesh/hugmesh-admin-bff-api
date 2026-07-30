package systems.hugmesh.adminbff.storage;

/**
 * One rendered element of the {@code node-storage-assignments} ConfigMap — the EXACT shape the
 * generator's {@code apps/13b-node-storage.yaml} ApplicationSet list-generator consumes (one
 * element per ACTIVE {@code storage_service_assignment} row). The field NAMES mirror the 13b
 * element documentation byte-for-byte:
 *
 * <pre>
 *   - { id: "a-1", service: owncast, pvc: owncast-data, nodeName: pi-edge-01,
 *       poolPath: /mnt/pool-1, namespace: hugmesh-backend, requested: "4", state: "active" }
 * </pre>
 *
 * <ul>
 *   <li>{@code id}        — the assignment id (the Application name suffix + dedup key).</li>
 *   <li>{@code service}   — the workload being placed ({@code service_name}).</li>
 *   <li>{@code pvc}       — the PVC the patch binds to the node-pinned PV ({@code pvc_name}).</li>
 *   <li>{@code nodeName}  — the node the pool is pinned to (resolved from the pool's device
 *                           residency: {@code pool.deviceId -> Device.hostname}).</li>
 *   <li>{@code poolPath}  — the pool's node-local path ({@code pool.poolPath}).</li>
 *   <li>{@code namespace} — the service's namespace (the placement target). There is no
 *                           per-assignment namespace column today, so the reconciler stamps a
 *                           single configured default ({@code node-storage.reconciler.service-namespace},
 *                           default {@code hugmesh-backend}, matching the JobLauncher default).</li>
 *   <li>{@code requested} — the slice in WHOLE Gi the PVC requests (capacity-aware; the BFF
 *                           already rejected over-subscription at assign time). Rendered as a
 *                           string because the 13b example carries it quoted ({@code "4"}).</li>
 *   <li>{@code state}     — always {@code "active"} for a rendered element; the 13b
 *                           {@code selector matchLabels state:"active"} keeps only these, so a
 *                           revoked/absent row simply drops out (prune unplaces it).</li>
 * </ul>
 *
 * <p>Render-only and secret-free by construction (no keys, no bytes-at-rest material).
 */
public record StorageAssignmentElement(
        String id,
        String service,
        String pvc,
        String nodeName,
        String poolPath,
        String namespace,
        String requested,
        String state) {

    /** One GiB in bytes (binary), for the {@code requestedBytes -> Gi} render. */
    public static final long GIB = 1024L * 1024L * 1024L;

    /**
     * Render the 13b element for an ACTIVE assignment, resolving {@code nodeName}/{@code poolPath}
     * from its pool and stamping the configured service namespace. {@code requested} is the
     * assignment's {@code requestedBytes} rounded UP to whole Gi (never 0 for a non-empty
     * request, so the PVC always asks for at least 1Gi), matching the capacity figure the
     * 13b overlay's PVC requests.
     */
    public static StorageAssignmentElement of(ServiceAssignment a, StoragePool pool,
                                              String nodeName, String serviceNamespace) {
        String node = (nodeName == null || nodeName.isBlank()) ? "" : nodeName;
        String path = (pool == null || pool.poolPath() == null) ? "" : pool.poolPath();
        return new StorageAssignmentElement(
                a.id(),
                a.serviceName(),
                a.pvcName(),
                node,
                path,
                serviceNamespace,
                Long.toString(toWholeGiCeil(a.requestedBytes())),
                ServiceAssignment.STATE_ACTIVE);
    }

    /** Bytes -> whole Gi, rounding UP; a positive sub-Gi request becomes 1, never 0. */
    static long toWholeGiCeil(long bytes) {
        if (bytes <= 0) {
            return 0;
        }
        return (bytes + GIB - 1) / GIB;
    }
}
