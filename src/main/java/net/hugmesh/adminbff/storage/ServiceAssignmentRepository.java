package net.hugmesh.adminbff.storage;

import org.springframework.stereotype.Repository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import net.hugmesh.commons.security.PrincipalDomain;

import java.time.Instant;

/**
 * Reactive (R2DBC) store for {@code storage_service_assignment} (schema in Liquibase
 * {@code db/changelog/085-node-storage.xml}). App-generated UUID ids, the verified
 * {@code scope == null || scope.scoped() ? WHERE domain=:domain : unscoped} branch for the
 * ADMIN read surface, {@code findActive}-before-insert idempotency, a CAS
 * {@code active -> revoked} that NEVER deletes (the row is the audit trail), and a monotonic
 * {@code generation} bumped on every mutate.
 *
 * <p>Backed by the Spring Data {@link ServiceAssignmentR2dbcRepository} (no raw
 * {@code DatabaseClient}); maps the {@link ServiceAssignmentRow} entity to/from the
 * {@link ServiceAssignment} domain record.
 *
 * <p>The over-subscription guard reads {@link #sumActiveRequestedBytes(String)} (the SUM of
 * ACTIVE {@code requested_bytes} for a pool) so the service can reject a placement that
 * would exceed the pool's {@code reserved_bytes} (capacity-aware). The active-by-pool set is
 * read UNSCOPED by the per-node export ({@link #listActiveForPool(String)}).
 */
@Repository
public class ServiceAssignmentRepository {

    private final ServiceAssignmentR2dbcRepository repo;

    public ServiceAssignmentRepository(ServiceAssignmentR2dbcRepository repo) {
        this.repo = repo;
    }

    // ── assign (findActive-then-insert idempotency) ─────────────────────────────

    /** The active assignment for (poolId, serviceName), if any — the idempotency check.
     *  UNSCOPED (the caller has passed the ownership gate). */
    public Mono<ServiceAssignment> findActive(String poolId, String serviceName) {
        return repo.findByPoolIdAndServiceNameAndState(poolId, serviceName,
                        ServiceAssignment.STATE_ACTIVE)
                .map(ServiceAssignmentRow::toDomain);
    }

    /**
     * The SUM of ACTIVE {@code requested_bytes} for a pool — the over-subscription guard's
     * working figure. The service rejects a NEW placement when
     * {@code sum + requestedBytes > pool.reservedBytes} (and is_exclusive pools reject any
     * second active assignment). Returns 0 when the pool has no active assignment.
     */
    public Mono<Long> sumActiveRequestedBytes(String poolId) {
        return repo.sumActiveRequestedBytes(poolId).defaultIfEmpty(0L);
    }

    /** The count of ACTIVE assignments for a pool — the is_exclusive guard + the
     *  pool-detach guard (a pool with an active assignment cannot be detached). */
    public Mono<Long> countActiveForPool(String poolId) {
        return repo.countActiveForPool(poolId).defaultIfEmpty(0L);
    }

    /**
     * Insert a new ACTIVE assignment (app-generated id) at the given generation, returning
     * it. The caller has resolved the pool FIRST, passed the ownership gate + the
     * over-subscription check, and stamped {@code domain} from the pool's residency
     * [FIX-NODEFAULT] before this insert.
     */
    public Mono<ServiceAssignment> insertActive(ServiceAssignment a, long generation) {
        Instant assignedAt = Instant.now();
        // INSERT omits id (filled from the (gen_random_uuid())::text column DEFAULT, changelog
        // 200); RETURNING id hands back the generated string, which we map into the persisted
        // ServiceAssignment with the SAME field order/values as before (revoke-audit NULL).
        return repo.insertReturningId(a.poolId(), a.serviceName(), a.pvcName(), a.requestedBytes(),
                        ServiceAssignment.STATE_ACTIVE, a.assignedBy(), assignedAt, a.domain(),
                        ServiceAssignment.PROP_PENDING, generation)
                .map(genId -> new ServiceAssignment(genId, a.poolId(), a.serviceName(), a.pvcName(),
                        a.requestedBytes(), ServiceAssignment.STATE_ACTIVE, a.assignedBy(),
                        assignedAt, null, null, a.domain(), ServiceAssignment.PROP_PENDING,
                        generation));
    }

    // ── read (admin surface, scoped) ────────────────────────────────────────────

    /** Assignments VISIBLE to the given tenant scope — the ADMIN read surface. A scoped
     *  admin sees ONLY their brand's rows; SUPERADMIN (unscoped) sees all. */
    public Flux<ServiceAssignment> list(PrincipalDomain scope) {
        if (scope == null || scope.scoped()) {
            String domain = scope == null ? PrincipalDomain.NO_DOMAIN : scope.domain();
            return repo.findByDomainOrderByAssignedAtDesc(domain).map(ServiceAssignmentRow::toDomain);
        }
        return repo.findByOrderByDomainAscAssignedAtDesc().map(ServiceAssignmentRow::toDomain);
    }

    /** A single assignment by id. UNSCOPED — the revoke flow resolves the row + the
     *  controller gates the surface. */
    public Mono<ServiceAssignment> findById(String id) {
        return repo.findById(id).map(ServiceAssignmentRow::toDomain);
    }

    // ── read (export / ApplicationSet, UNSCOPED) ────────────────────────────────

    /** ALL active assignments for one pool. UNSCOPED — the per-node export + the 13b
     *  ApplicationSet working set. */
    public Flux<ServiceAssignment> listActiveForPool(String poolId) {
        return repo.findByPoolIdAndStateOrderByServiceName(poolId, ServiceAssignment.STATE_ACTIVE)
                .map(ServiceAssignmentRow::toDomain);
    }

    /** ALL active assignments (every brand). UNSCOPED — the 13b ApplicationSet
     *  list-generator full working set. */
    public Flux<ServiceAssignment> listActiveAll() {
        return repo.findByStateOrderByPoolIdAscServiceNameAsc(ServiceAssignment.STATE_ACTIVE)
                .map(ServiceAssignmentRow::toDomain);
    }

    /** The current maximum {@code generation} across ALL assignment rows — the monotonic
     *  counter the export stamps. Returns 0 when the table is empty. */
    public Mono<Long> maxGeneration() {
        return repo.maxGeneration().defaultIfEmpty(0L);
    }

    // ── revoke (CAS, audited, generation bump) ──────────────────────────────────

    /**
     * Compare-and-swap {@code active -> revoked} for one assignment id at a NEW generation,
     * guarded on the current state so only ONE writer wins (returns rows-updated: 1 = won +
     * audit stamped, 0 = already revoked / absent / out of scope). The row is NEVER deleted
     * — {@code revoked_at}/{@code revoked_by} stamp the audit. A scoped principal can only
     * revoke a row in their own brand; SUPERADMIN any.
     */
    public Mono<Long> revoke(String id, String revokedBy, long newGeneration, PrincipalDomain scope) {
        if (scope == null || scope.scoped()) {
            String domain = scope == null ? PrincipalDomain.NO_DOMAIN : scope.domain();
            return repo.revokeScoped(id, revokedBy, newGeneration, domain);
        }
        return repo.revokeAll(id, revokedBy, newGeneration);
    }

    /** Record the GitOps propagation outcome (pending/applied/failed/degraded) for a row.
     *  UNSCOPED — driven by the reconcile/ack path (PR7/PR8). */
    public Mono<Long> updatePropagationState(String id, String propagationState) {
        return repo.updatePropagationState(id, propagationState);
    }
}
