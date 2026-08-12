package net.hugmesh.adminbff.domainlock;

import org.springframework.data.r2dbc.repository.Modifying;
import org.springframework.data.r2dbc.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.time.Instant;

/**
 * Reactive (R2DBC) Spring Data store for {@code domain_lock} (changeset 009 + 010).
 * Reads are derived finders; the two state-guarded / partial UPDATEs are {@code @Query}
 * static-final constants (a CAS-on-state UPDATE is not derivable). The {@link
 * DomainLockRepository} facade maps rows to/from the {@link DomainLock} domain record.
 *
 * <p>DB-GENERATED PK (changelog 200): the varchar(36) {@code id} carries a
 * {@code (gen_random_uuid())::text} DEFAULT; the INSERT OMITS {@code id} and appends
 * {@code RETURNING id} to read the database-generated string back, returned as a
 * {@code Mono<String>} (the deterministic, mod-bff-proven path).
 */
public interface DomainLockRowRepository extends ReactiveCrudRepository<DomainLockRow, String> {

    /**
     * Insert a new lock with a DB-generated id (id OMITTED → filled from the column DEFAULT;
     * {@code RETURNING id} reads the generated varchar(36) back). The 9 supplied columns
     * match the {@link DomainLockRow} column order (id excluded).
     */
    String INSERT_RETURNING_ID = """
            INSERT INTO domain_lock \
            (casdoor_user, localpart, role, state, created_at, propagation_state, reason, \
             set_by, domain) \
            VALUES (:casdoor_user, :localpart, :role, :state, :created_at, :propagation_state, \
             :reason, :set_by, :domain) \
            RETURNING id""";

    @Query(INSERT_RETURNING_ID)
    Mono<String> insertReturningId(@Param("casdoor_user") String casdoorUser,
                                   @Param("localpart") String localpart,
                                   @Param("role") String role,
                                   @Param("state") String state,
                                   @Param("created_at") Instant createdAt,
                                   @Param("propagation_state") String propagationState,
                                   @Param("reason") String reason,
                                   @Param("set_by") String setBy,
                                   @Param("domain") String domain);

    Mono<DomainLockRow> findByCasdoorUserAndRoleAndState(String casdoorUser, String role, String state);

    Mono<DomainLockRow> findByCasdoorUserAndRoleAndStateAndDomain(
            String casdoorUser, String role, String state, String domain);

    Flux<DomainLockRow> findByRoleAndStateOrderByCasdoorUser(String role, String state);

    Flux<DomainLockRow> findByLocalpartAndRoleAndState(String localpart, String role, String state);

    Flux<DomainLockRow> findByStateOrderByRoleAscCasdoorUserAsc(String state);

    Flux<DomainLockRow> findByStateAndDomainOrderByRoleAscCasdoorUserAsc(String state, String domain);

    /** CAS {@code active -> removed} for one id; returns rows updated (1=won, 0=lost). */
    String MARK_REMOVED =
            "UPDATE domain_lock SET state = 'removed' WHERE id = :id AND state = 'active'";

    @Modifying
    @Query(MARK_REMOVED)
    Mono<Long> markRemoved(String id);

    /** Record the force-local-leg outcome for a row. */
    String UPDATE_PROP =
            "UPDATE domain_lock SET propagation_state = :ps WHERE id = :id";

    @Modifying
    @Query(UPDATE_PROP)
    Mono<Long> updatePropagationState(String id, String ps);
}
