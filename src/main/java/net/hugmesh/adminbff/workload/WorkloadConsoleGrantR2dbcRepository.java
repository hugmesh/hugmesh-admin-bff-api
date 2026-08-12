package net.hugmesh.adminbff.workload;

import org.springframework.data.r2dbc.repository.Modifying;
import org.springframework.data.r2dbc.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.time.Instant;

/**
 * Reactive (R2DBC) Spring Data store for {@code workload_console_grant} (changeset 110). The
 * active lookup, the scoped/unscoped admin lists, and the TTL-expiry scan are derived finders;
 * the {@code MAX(generation)} aggregate, the two state-guarded CAS UPDATEs (revoke + expire),
 * and the propagation-state partial UPDATE are {@code @Query} static-final constants (an
 * aggregate and CAS-on-state UPDATEs are not derivable). The
 * {@link WorkloadConsoleGrantRepository} facade maps rows to/from the
 * {@link WorkloadConsoleGrant} domain record.
 */
public interface WorkloadConsoleGrantR2dbcRepository
        extends ReactiveCrudRepository<WorkloadConsoleGrantRow, String> {

    /**
     * Insert a new ACTIVE grant with a DB-generated id (changelog 200): {@code id} is OMITTED →
     * filled from the {@code (gen_random_uuid())::text} column DEFAULT; {@code RETURNING id} reads
     * the generated varchar(36) back ({@code Mono<String>}). The not-yet-set {@code revoked_at}/
     * {@code revoked_by} are OMITTED (default NULL — the fresh-grant shape). Columns match the
     * {@link WorkloadConsoleGrantRow} order (id + revoked_at + revoked_by excluded).
     */
    String INSERT_RETURNING_ID = """
            INSERT INTO workload_console_grant \
            (grantee, target_domain, access_level, log_access, state, granted_by, granted_at, \
             expires_at, domain, propagation_state, generation) \
            VALUES (:grantee, :targetDomain, :accessLevel, :logAccess, :state, :grantedBy, \
             :grantedAt, :expiresAt, :domain, :propagationState, :generation) \
            RETURNING id""";

    @Query(INSERT_RETURNING_ID)
    Mono<String> insertReturningId(@Param("grantee") String grantee,
                                   @Param("targetDomain") String targetDomain,
                                   @Param("accessLevel") String accessLevel,
                                   @Param("logAccess") boolean logAccess,
                                   @Param("state") String state,
                                   @Param("grantedBy") String grantedBy,
                                   @Param("grantedAt") Instant grantedAt,
                                   @Param("expiresAt") Instant expiresAt,
                                   @Param("domain") String domain,
                                   @Param("propagationState") String propagationState,
                                   @Param("generation") long generation);

    /** The active grant for (grantee, targetDomain), if any — the authz-predicate read. */
    Mono<WorkloadConsoleGrantRow> findByGranteeAndTargetDomainAndState(
            String grantee, String targetDomain, String state);

    /** Grants for a brand, grantee then newest first — the scoped admin read. */
    Flux<WorkloadConsoleGrantRow> findByDomainOrderByGranteeAscGrantedAtDesc(String domain);

    /** ALL grants (unscoped SUPERADMIN), domain then grantee then newest first. */
    Flux<WorkloadConsoleGrantRow> findByOrderByDomainAscGranteeAscGrantedAtDesc();

    /** Active grants whose TTL has elapsed — the expiry-sweep working set. */
    Flux<WorkloadConsoleGrantRow> findByStateAndExpiresAtLessThanEqualOrderByExpiresAt(
            String state, Instant now);

    /** The current MAX(generation) across ALL grant rows; 0 when empty. */
    String MAX_GENERATION = "SELECT COALESCE(MAX(generation), 0) FROM workload_console_grant";

    @Query(MAX_GENERATION)
    Mono<Long> maxGeneration();

    /** CAS {@code active -> revoked} at a new generation, stamping audit. */
    String REVOKE =
            "UPDATE workload_console_grant "
            + "SET state = 'revoked', revoked_at = now(), revoked_by = :by, "
            + "    generation = :gen, propagation_state = 'pending' "
            + "WHERE id = :id AND state = 'active'";

    @Modifying
    @Query(REVOKE)
    Mono<Long> revoke(String id, String by, long gen);

    /** CAS {@code active -> expired} at a new generation. */
    String MARK_EXPIRED =
            "UPDATE workload_console_grant "
            + "SET state = 'expired', generation = :gen, propagation_state = 'pending' "
            + "WHERE id = :id AND state = 'active'";

    @Modifying
    @Query(MARK_EXPIRED)
    Mono<Long> markExpired(String id, long gen);

    /** Record the propagation outcome for a row. */
    String UPDATE_PROP = "UPDATE workload_console_grant SET propagation_state = :ps WHERE id = :id";

    @Modifying
    @Query(UPDATE_PROP)
    Mono<Long> updatePropagationState(String id, String ps);
}
