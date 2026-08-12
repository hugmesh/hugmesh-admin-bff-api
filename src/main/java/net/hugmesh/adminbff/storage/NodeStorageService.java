package net.hugmesh.adminbff.storage;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import net.hugmesh.adminbff.device.Device;
import net.hugmesh.adminbff.device.DeviceRegistryRepository;
import net.hugmesh.commons.security.PrincipalDomain;

/**
 * Write/read surface for NODE STORAGE — the ADDITIONAL storage an operator ATTACHES to a
 * specific mesh node so services can use SPACE on that node ({@code node_storage_pool} +
 * {@code storage_service_assignment}, schema 085). CLONES the
 * {@link net.hugmesh.adminbff.device.SshLicenseService} desired-state idioms (resolve
 * the target FIRST, idempotent findActive-then-insert, CAS-revoke audit, monotonic
 * generation, residency-stamped domain) with ONE deliberate DIVERGENCE: the OWNERSHIP
 * ALLOW/DENY matrix.
 *
 * <h3>OWNERSHIP ALLOW/DENY matrix (the load-bearing security)</h3>
 * Storage is ADMIN-CAPABLE (not superadmin-only, unlike SSH licensing) but OWNERSHIP-gated.
 * For a caller {@link PrincipalDomain} acting on a resolved node {@link Device}:
 * <ul>
 *   <li><b>SUPERADMIN</b> ({@code scope.superadmin()}) — UNRESTRICTED: any node, any
 *       domain, ADMIN- or SUPERADMIN-owned. ALLOW.</li>
 *   <li><b>ADMIN</b> ({@code scope.scoped()}) acting on an <b>ADMIN-owned</b> node in their
 *       <b>own residency domain</b> ({@code device.domain == scope.domain}) — ALLOW.</li>
 *   <li><b>ADMIN</b> acting on a <b>SUPERADMIN-owned</b> node — DENY (those are
 *       SUPERADMIN-only, regardless of domain).</li>
 *   <li><b>ADMIN</b> acting on an ADMIN-owned node in <b>another</b> domain — DENY
 *       (cross-domain).</li>
 * </ul>
 * A DENY is a {@link StorageAccessDeniedException} (controller -&gt; 403). The node is
 * resolved FIRST so the gate fires before ANY write and the pool/assignment {@code domain}
 * is stamped from the device's RESIDENCY [FIX-NODEFAULT], never the caller.
 *
 * <h3>Capacity-aware placement (over-subscription reject)</h3>
 * An assign is rejected (422) when the pool's already-committed ACTIVE slices plus the new
 * request would exceed the pool's {@code reserved_bytes}, or when an {@code is_exclusive}
 * pool already holds an active assignment. {@code reserved_bytes} is the operator's claim;
 * the node-agent's df is the FINAL authority (verified at reconcile, PR6) — this API guard
 * is the first, declarative gate.
 */
@Service
public class NodeStorageService {

    private static final Logger log = LoggerFactory.getLogger(NodeStorageService.class);

    private final StoragePoolRepository pools;
    private final ServiceAssignmentRepository assignments;
    private final DeviceRegistryRepository devices;

    public NodeStorageService(StoragePoolRepository pools, ServiceAssignmentRepository assignments,
                              DeviceRegistryRepository devices) {
        this.pools = pools;
        this.assignments = assignments;
        this.devices = devices;
    }

    // ════════════════════════ OWNERSHIP ALLOW/DENY ═════════════════════════════

    /**
     * The ownership ALLOW/DENY predicate (pure — unit-testable in isolation). Returns null
     * when ALLOWED, or a human-readable DENY reason. SUPERADMIN is unrestricted; an ADMIN is
     * allowed ONLY on an ADMIN-owned node in their own residency domain.
     */
    static String denyReason(PrincipalDomain scope, Device device) {
        if (scope != null && scope.superadmin()) {
            return null;   // SUPERADMIN: unrestricted
        }
        // ADMIN (scoped) path.
        if (device.isSuperadminOwned()) {
            return "node " + device.id() + " is SUPERADMIN-owned — only a SUPERADMIN may "
                    + "manage its storage";
        }
        String callerDomain = scope == null ? PrincipalDomain.NO_DOMAIN : scope.domain();
        if (!device.domain().equals(callerDomain)) {
            return "node " + device.id() + " is resident in domain '" + device.domain()
                    + "' — an ADMIN may only manage storage on own-domain nodes (caller domain '"
                    + callerDomain + "')";
        }
        return null;   // ADMIN: own-domain, ADMIN-owned -> ALLOW
    }

    /** Resolve the node by id (fail with 422 IllegalArgumentException if unknown), then
     *  apply the ownership gate (fail with 403 StorageAccessDeniedException on DENY),
     *  returning the resolved device for residency-stamping. */
    private Mono<Device> resolveAndGate(String deviceId, PrincipalDomain scope) {
        return devices.findById(deviceId)
                .switchIfEmpty(Mono.error(new IllegalArgumentException(
                        "node " + deviceId + " is not registered")))
                .flatMap(device -> {
                    String deny = denyReason(scope, device);
                    if (deny != null) {
                        return Mono.error(new StorageAccessDeniedException(deny));
                    }
                    return Mono.just(device);
                });
    }

    // ════════════════════════ pool attach / detach ═════════════════════════════

    /**
     * Idempotently ATTACH a storage pool to {@code deviceId}. Resolves the node FIRST →
     * ownership gate → stamps the pool {@code domain} from the device's residency
     * [FIX-NODEFAULT]. An existing active (device, disk) pool is returned unchanged (the
     * no-op attach); otherwise a new active row is written at the next monotonic generation.
     */
    public Mono<StoragePool> attachPool(String deviceId, String diskSerial, String poolPath,
                                        long reservedBytes, boolean isExclusive, String filesystem,
                                        PrincipalDomain scope, String createdBy) {
        if (reservedBytes <= 0) {
            return Mono.error(new IllegalArgumentException("reservedBytes must be > 0"));
        }
        // Gate on device ownership then idempotently insert a new pool row.
        return resolveAndGate(deviceId, scope)
                .flatMap(device -> attachPoolForDevice(device, deviceId, diskSerial, poolPath,
                        reservedBytes, isExclusive, filesystem, createdBy));
    }

    /**
     * DETACH a pool by id (CAS active->detached at the next generation). Resolves the pool's
     * node FIRST → ownership gate. REFUSES (422) when the pool still has an ACTIVE assignment
     * (detaching live storage would orphan a running service's PV — the operator must revoke
     * the assignment first). Returns rows-updated (1 = detached, 0 = already detached/absent).
     */
    public Mono<Long> detachPool(String poolId, PrincipalDomain scope, String detachedBy) {
        return pools.findById(poolId)
                .switchIfEmpty(Mono.error(new IllegalArgumentException("pool " + poolId + " not found")))
                // Gate on device ownership, check for active assignments, then CAS to detached.
                .flatMap(pool -> detachPoolIfSafe(pool, poolId, scope, detachedBy));
    }

    // ════════════════════════ service assign / revoke ══════════════════════════

    /**
     * Idempotently ASSIGN {@code serviceName} to {@code poolId}. Resolves the pool's node
     * FIRST → ownership gate → over-subscription check → stamps the assignment {@code domain}
     * from the pool's residency [FIX-NODEFAULT]. An existing active (pool, service)
     * assignment is returned unchanged (the no-op assign).
     */
    public Mono<ServiceAssignment> assignService(String poolId, String serviceName, String pvcName,
                                                  long requestedBytes, PrincipalDomain scope,
                                                  String assignedBy) {
        if (requestedBytes <= 0) {
            return Mono.error(new IllegalArgumentException("requestedBytes must be > 0"));
        }
        return pools.findById(poolId)
                .switchIfEmpty(Mono.error(new IllegalArgumentException("pool " + poolId + " not found")))
                // Gate on pool-active state + device ownership + capacity, then idempotently assign.
                .flatMap(pool -> assignServiceForPool(pool, poolId, serviceName, pvcName,
                        requestedBytes, scope, assignedBy));
    }

    /** Over-subscription + exclusivity guard: reject (422) a placement that would exceed the
     *  pool's reserved_bytes, or any second active assignment on an is_exclusive pool. */
    private Mono<Void> capacityCheck(StoragePool pool, long requestedBytes) {
        return assignments.countActiveForPool(pool.id())
                // Exclusive-pool guard, then byte-reservation guard.
                .flatMap(activeCount -> checkCapacityAfterCount(pool, activeCount, requestedBytes));
    }

    /** Resolve the device, gate ownership, then idempotently insert a pool row for the device. */
    private Mono<StoragePool> attachPoolForDevice(net.hugmesh.adminbff.device.Device device,
                                                   String deviceId, String diskSerial, String poolPath,
                                                   long reservedBytes, boolean isExclusive,
                                                   String filesystem, String createdBy) {
        return pools.findActiveDisk(deviceId, diskSerial)
                .doOnNext(existing -> log.info(
                        "[node-storage] pool already active for device {} disk {} (id={}) — no-op",
                        deviceId, diskSerial, existing.id()))
                // Insert a new pool if none exists yet for this device+disk.
                .switchIfEmpty(Mono.defer(() -> insertPoolRow(device, deviceId, diskSerial, poolPath,
                        reservedBytes, isExclusive, filesystem, createdBy)));
    }

    /** Blocking-helper: allocate a generation slot and insert a new pool row for the device+disk. */
    private Mono<StoragePool> insertPoolRow(net.hugmesh.adminbff.device.Device device,
                                             String deviceId, String diskSerial, String poolPath,
                                             long reservedBytes, boolean isExclusive,
                                             String filesystem, String createdBy) {
        return pools.maxGeneration().flatMap(maxGen -> {
            StoragePool draft = new StoragePool(null, deviceId, diskSerial, poolPath,
                    reservedBytes, isExclusive, filesystem, StoragePool.STATE_ACTIVE,
                    device.domain(), StoragePool.PROP_PENDING, maxGen + 1, createdBy, null, null, null);
            return pools.insertActive(draft, maxGen + 1)
                    .doOnNext(p -> log.info(
                            "[node-storage] attached pool {} device {} domain={} reserved={} gen={} (id={})",
                            diskSerial, deviceId, device.domain(), reservedBytes, p.generation(), p.id()));
        });
    }

    /** Gate on device ownership, check for active assignments, then CAS the pool to detached. */
    private Mono<Long> detachPoolIfSafe(StoragePool pool, String poolId, PrincipalDomain scope,
                                         String detachedBy) {
        return resolveAndGate(pool.deviceId(), scope)
                .then(assignments.countActiveForPool(poolId))
                // Reject if any assignment is still active; otherwise CAS to detached.
                .flatMap(active -> detachIfNoActiveAssignments(active, poolId, detachedBy, scope));
    }

    /** Require zero active assignments then CAS the pool to detached state. */
    private Mono<Long> detachIfNoActiveAssignments(long active, String poolId,
                                                    String detachedBy, PrincipalDomain scope) {
        if (active > 0) {
            return Mono.error(new IllegalArgumentException(
                    "pool " + poolId + " has " + active + " active assignment(s) — "
                    + "revoke them before detaching (node-pinned PVs would orphan)"));
        }
        return pools.maxGeneration().flatMap(maxGen ->
                pools.detach(poolId, detachedBy, maxGen + 1, scope)
                        .doOnNext(n -> log.info("[node-storage] detach pool id={} by={} gen={} rows={}",
                                poolId, detachedBy, maxGen + 1, n)));
    }

    /** Validate pool-active state, gate ownership, and idempotently assign the service. */
    private Mono<ServiceAssignment> assignServiceForPool(StoragePool pool, String poolId,
                                                          String serviceName, String pvcName,
                                                          long requestedBytes, PrincipalDomain scope,
                                                          String assignedBy) {
        if (!pool.isActive()) {
            return Mono.error(new IllegalArgumentException(
                    "pool " + poolId + " is not active (state=" + pool.state() + ")"));
        }
        return resolveAndGate(pool.deviceId(), scope).flatMap(device ->
                assignments.findActive(poolId, serviceName)
                        .doOnNext(existing -> log.info(
                                "[node-storage] assignment already active for pool {} service {} (id={}) — no-op",
                                poolId, serviceName, existing.id()))
                        .switchIfEmpty(Mono.defer(() -> capacityCheck(pool, requestedBytes)
                                .then(insertAssignment(pool, serviceName, pvcName,
                                        requestedBytes, assignedBy)))));
    }

    /** Apply the exclusivity check, then sum committed bytes and reject if over-subscribed. */
    private Mono<Void> checkCapacityAfterCount(StoragePool pool, long activeCount, long requestedBytes) {
        if (pool.isExclusive() && activeCount > 0) {
            return Mono.error(new IllegalArgumentException(
                    "pool " + pool.id() + " is exclusive and already has an active assignment"));
        }
        return assignments.sumActiveRequestedBytes(pool.id()).flatMap(committed -> {
            long total = committed + requestedBytes;
            if (total > pool.reservedBytes()) {
                return Mono.<Void>error(new IllegalArgumentException(
                        "over-subscription: pool " + pool.id() + " reserved=" + pool.reservedBytes()
                        + " committed=" + committed + " requested=" + requestedBytes
                        + " (would exceed reserved)"));
            }
            return Mono.empty();
        });
    }

    private Mono<ServiceAssignment> insertAssignment(StoragePool pool, String serviceName,
                                                     String pvcName, long requestedBytes,
                                                     String assignedBy) {
        return assignments.maxGeneration().flatMap(maxGen -> {
            ServiceAssignment draft = new ServiceAssignment(null, pool.id(), serviceName, pvcName,
                    requestedBytes, ServiceAssignment.STATE_ACTIVE, assignedBy, null, null, null,
                    pool.domain(), ServiceAssignment.PROP_PENDING, maxGen + 1);
            return assignments.insertActive(draft, maxGen + 1)
                    .doOnNext(a -> log.info(
                            "[node-storage] assigned service {} to pool {} domain={} requested={} gen={} (id={})",
                            serviceName, pool.id(), pool.domain(), requestedBytes, a.generation(), a.id()));
        });
    }

    /**
     * REVOKE an assignment by id (CAS active->revoked at the next generation). Resolves the
     * assignment → its pool → the pool's node FIRST → ownership gate. Returns rows-updated
     * (1 = revoked, 0 = already revoked/absent/out of scope).
     */
    public Mono<Long> revokeAssignment(String assignmentId, PrincipalDomain scope, String revokedBy) {
        return assignments.findById(assignmentId)
                .switchIfEmpty(Mono.error(new IllegalArgumentException(
                        "assignment " + assignmentId + " not found")))
                .flatMap(a -> pools.findById(a.poolId())
                        .switchIfEmpty(Mono.error(new IllegalArgumentException(
                                "pool " + a.poolId() + " not found")))
                        .flatMap(pool -> resolveAndGate(pool.deviceId(), scope))
                        .then(assignments.maxGeneration())
                        .flatMap(maxGen -> assignments.revoke(assignmentId, revokedBy, maxGen + 1, scope)
                                .doOnNext(n -> log.info(
                                        "[node-storage] revoke assignment id={} by={} gen={} rows={}",
                                        assignmentId, revokedBy, maxGen + 1, n))));
    }

    // ════════════════════════ read (admin surface, scoped) ═════════════════════

    /** Pools VISIBLE to the given tenant scope — ADMIN own-domain only, SUPERADMIN all. */
    public Flux<StoragePool> listPools(PrincipalDomain scope) {
        return pools.list(scope);
    }

    /** Assignments VISIBLE to the given tenant scope — ADMIN own-domain only, SUPERADMIN
     *  all. */
    public Flux<ServiceAssignment> listAssignments(PrincipalDomain scope) {
        return assignments.list(scope);
    }
}
