package net.hugmesh.adminbff.appeal;

import org.springframework.data.r2dbc.repository.Modifying;
import org.springframework.data.r2dbc.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.time.Instant;

/**
 * Reactive (R2DBC) Spring Data store for {@code account_appeal} (changeset 250). CLONES
 * {@code DesktopInstallRequestR2dbcRepository}'s shape: derived finders for the
 * double-scoped user read + the scoped/unscoped admin read, and a {@code @Query}
 * CAS decide (a status-guarded stamping UPDATE is not derivable).
 */
public interface AccountAppealR2dbcRepository extends ReactiveCrudRepository<AccountAppealRow, String> {

    /**
     * Insert a new PENDING appeal with a DB-generated id (changeset 250): {@code id} is
     * OMITTED -> filled from the {@code (gen_random_uuid())::text} column DEFAULT;
     * {@code RETURNING id} reads the generated varchar(36) back. {@code decided_at}/
     * {@code decided_by} are OMITTED (default NULL — the fresh-appeal shape).
     */
    String INSERT_RETURNING_ID = """
            INSERT INTO account_appeal \
            (user_sub, handle, domain, reason, contact_email, status, submitted_at) \
            VALUES (:userSub, :handle, :domain, :reason, :contactEmail, :status, :submittedAt) \
            RETURNING id""";

    @Query(INSERT_RETURNING_ID)
    Mono<String> insertReturningId(@Param("userSub") String userSub,
                                   @Param("handle") String handle,
                                   @Param("domain") String domain,
                                   @Param("reason") String reason,
                                   @Param("contactEmail") String contactEmail,
                                   @Param("status") String status,
                                   @Param("submittedAt") Instant submittedAt);

    /** The appellant's OWN appeals in their OWN brand, newest first (cross-user isolation). */
    Flux<AccountAppealRow> findByUserSubAndDomainOrderBySubmittedAtDesc(String userSub, String domain);

    /** The appellant's most recent PENDING appeal, if any (idempotent re-submit guard). */
    Mono<AccountAppealRow> findFirstByUserSubAndDomainAndStatusOrderBySubmittedAtDesc(
            String userSub, String domain, String status);

    /** Appeals for a brand, newest first — the scoped admin inbox. */
    Flux<AccountAppealRow> findByDomainOrderBySubmittedAtDesc(String domain);

    /** ALL appeals (unscoped SUPERADMIN), domain then newest first. */
    Flux<AccountAppealRow> findByOrderByDomainAscSubmittedAtDesc();

    /** One appeal by id within a brand (scoped resolve). */
    Mono<AccountAppealRow> findByIdAndDomain(String id, String domain);

    /** CAS {@code PENDING -> newStatus} for one appeal in a brand, stamping the decider. */
    String DECIDE_SCOPED =
            "UPDATE account_appeal "
            + "SET status = :st, decided_by = :by, decided_at = now() "
            + "WHERE id = :id AND status = 'PENDING' AND domain = :domain";

    @Modifying
    @Query(DECIDE_SCOPED)
    Mono<Long> decideScoped(String id, String st, String by, String domain);

    /** CAS {@code PENDING -> newStatus} for one appeal (unscoped SUPERADMIN). */
    String DECIDE_ALL =
            "UPDATE account_appeal "
            + "SET status = :st, decided_by = :by, decided_at = now() "
            + "WHERE id = :id AND status = 'PENDING'";

    @Modifying
    @Query(DECIDE_ALL)
    Mono<Long> decideAll(String id, String st, String by);
}
