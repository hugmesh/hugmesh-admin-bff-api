package systems.hugmesh.adminbff.storage;

import org.springframework.data.r2dbc.repository.Modifying;
import org.springframework.data.r2dbc.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.time.Instant;

/**
 * Reactive (R2DBC) Spring Data store for {@code storage_service_assignment} (changeset 085).
 * The active lookup, scoped/unscoped admin lists, and per-pool/global active scans are derived
 * finders; the {@code SUM}/{@code COUNT}/{@code MAX} aggregates and the two state-guarded CAS
 * revoke UPDATEs (scoped + unscoped) plus the propagation-state partial UPDATE are
 * {@code @Query} static-final constants (aggregates and CAS-on-state UPDATEs are not
 * derivable). The {@link ServiceAssignmentRepository} facade maps rows to/from the
 * {@link ServiceAssignment} domain record.
 *
 * <p>DB-GENERATED PK (changelog 200): the varchar(36) {@code id} carries a
 * {@code (gen_random_uuid())::text} DEFAULT; the INSERT OMITS {@code id} and appends
 * {@code RETURNING id} to read the database-generated string back ({@code Mono<String>}).
 */
public interface ServiceAssignmentR2dbcRepository
        extends ReactiveCrudRepository<ServiceAssignmentRow, String> {

    /**
     * Insert a new assignment with a DB-generated id (id OMITTED → filled from the column
     * DEFAULT; {@code RETURNING id} reads the generated varchar(36) back). The nullable
     * {@code revoked_at}/{@code revoked_by} are OMITTED (default NULL — the fresh-assignment
     * shape). The supplied columns match the {@link ServiceAssignmentRow} column order
     * (id + revoke-audit columns excluded).
     */
    String INSERT_RETURNING_ID = """
            INSERT INTO storage_service_assignment \
            (pool_id, service_name, pvc_name, requested_bytes, state, assigned_by, \
             assigned_at, domain, propagation_state, generation) \
            VALUES (:pool_id, :service_name, :pvc_name, :requested_bytes, :state, \
             :assigned_by, :assigned_at, :domain, :propagation_state, :generation) \
            RETURNING id""";

    @Query(INSERT_RETURNING_ID)
    Mono<String> insertReturningId(@Param("pool_id") String poolId,
                                   @Param("service_name") String serviceName,
                                   @Param("pvc_name") String pvcName,
                                   @Param("requested_bytes") long requestedBytes,
                                   @Param("state") String state,
                                   @Param("assigned_by") String assignedBy,
                                   @Param("assigned_at") Instant assignedAt,
                                   @Param("domain") String domain,
                                   @Param("propagation_state") String propagationState,
                                   @Param("generation") long generation);

    /** The active assignment for (poolId, serviceName), if any — the idempotency check. */
    Mono<ServiceAssignmentRow> findByPoolIdAndServiceNameAndState(
            String poolId, String serviceName, String state);

    /** Assignments for a brand, newest first — the scoped admin read. */
    Flux<ServiceAssignmentRow> findByDomainOrderByAssignedAtDesc(String domain);

    /** ALL assignments (unscoped SUPERADMIN), domain then newest first. */
    Flux<ServiceAssignmentRow> findByOrderByDomainAscAssignedAtDesc();

    /** ALL active assignments for one pool, by service name — the per-node export. */
    Flux<ServiceAssignmentRow> findByPoolIdAndStateOrderByServiceName(String poolId, String state);

    /** ALL active assignments (every brand), pool then service — the ApplicationSet set. */
    Flux<ServiceAssignmentRow> findByStateOrderByPoolIdAscServiceNameAsc(String state);

    /** The SUM of ACTIVE requested_bytes for a pool — the over-subscription guard. */
    String SUM_ACTIVE =
            "SELECT COALESCE(SUM(requested_bytes), 0) FROM storage_service_assignment "
            + "WHERE pool_id = :poolId AND state = 'active'";

    @Query(SUM_ACTIVE)
    Mono<Long> sumActiveRequestedBytes(String poolId);

    /** The COUNT of ACTIVE assignments for a pool — the is_exclusive + detach guards. */
    String COUNT_ACTIVE =
            "SELECT COUNT(*) FROM storage_service_assignment "
            + "WHERE pool_id = :poolId AND state = 'active'";

    @Query(COUNT_ACTIVE)
    Mono<Long> countActiveForPool(String poolId);

    /** The current MAX(generation) across ALL assignment rows; 0 when empty. */
    String MAX_GENERATION = "SELECT COALESCE(MAX(generation), 0) FROM storage_service_assignment";

    @Query(MAX_GENERATION)
    Mono<Long> maxGeneration();

    /** CAS {@code active -> revoked} for one id in a brand, stamping audit + bumping gen. */
    String REVOKE_SCOPED =
            "UPDATE storage_service_assignment "
            + "SET state = 'revoked', revoked_at = now(), revoked_by = :by, "
            + "    generation = :gen, propagation_state = 'pending' "
            + "WHERE id = :id AND state = 'active' AND domain = :domain";

    @Modifying
    @Query(REVOKE_SCOPED)
    Mono<Long> revokeScoped(String id, String by, long gen, String domain);

    /** CAS {@code active -> revoked} for one id (unscoped SUPERADMIN). */
    String REVOKE_ALL =
            "UPDATE storage_service_assignment "
            + "SET state = 'revoked', revoked_at = now(), revoked_by = :by, "
            + "    generation = :gen, propagation_state = 'pending' "
            + "WHERE id = :id AND state = 'active'";

    @Modifying
    @Query(REVOKE_ALL)
    Mono<Long> revokeAll(String id, String by, long gen);

    /** Record the GitOps propagation outcome for a row. */
    String UPDATE_PROP =
            "UPDATE storage_service_assignment SET propagation_state = :ps WHERE id = :id";

    @Modifying
    @Query(UPDATE_PROP)
    Mono<Long> updatePropagationState(String id, String ps);
}
