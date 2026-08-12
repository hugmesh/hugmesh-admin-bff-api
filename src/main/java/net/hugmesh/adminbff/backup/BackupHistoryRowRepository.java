package net.hugmesh.adminbff.backup;

import org.springframework.data.r2dbc.repository.Modifying;
import org.springframework.data.r2dbc.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.time.Instant;
import java.util.UUID;

/**
 * Reactive (R2DBC) Spring Data store for {@code backup_history} (changeset 050). Reads
 * are derived; the status transition is a COALESCE partial UPDATE expressed as an
 * {@code @Modifying @Query} static-final constant (a full-entity save would require a
 * prior read and would not honour the COALESCE keep-existing semantics).
 *
 * <p>DB-GENERATED UUID PK (changelog 200): the {@code id} is NO LONGER minted in Java. The
 * {@code backup_history.id} column carries a {@code DEFAULT gen_random_uuid()} (pgcrypto), so
 * the INSERT OMITS {@code id} and appends {@code RETURNING id} to read the database-generated
 * UUID back. The INSERT is an explicit {@code @Query} (the deterministic, mod-bff-proven
 * path) returning {@code Mono<UUID>} rather than a {@code save()} with an assigned id.
 */
public interface BackupHistoryRowRepository extends ReactiveCrudRepository<BackupHistoryRow, UUID> {

    /** Newest-first history ({@code ORDER BY created_at DESC}) — SUPERADMIN (all brands). */
    Flux<BackupHistoryRow> findAllByOrderByCreatedAtDesc();

    /** Newest-first history for ONE tenant — the scoped-ADMIN read predicate. Explicit
     *  {@code @Query} so the entity needs no {@code domain} field ({@code SELECT *} returns
     *  the column; R2DBC ignores the unmapped one). */
    @Query("SELECT * FROM backup_history WHERE domain = :domain ORDER BY created_at DESC")
    Flux<BackupHistoryRow> findByDomainOrderByCreatedAtDesc(@Param("domain") String domain);

    /** A single backup row VISIBLE to one tenant — scopes detail + restore-source resolution. */
    @Query("SELECT * FROM backup_history WHERE id = :id AND domain = :domain")
    Mono<BackupHistoryRow> findByIdAndDomain(@Param("id") UUID id, @Param("domain") String domain);

    /**
     * Insert a freshly-queued backup row with a DB-generated id. The {@code id} is OMITTED
     * so Postgres fills it from the {@code gen_random_uuid()} column DEFAULT (changelog 200);
     * {@code RETURNING id} reads the generated UUID back. A plain (non-{@code @Modifying})
     * {@code @Query} returning the new id. Static-final SQL constant per the data-access
     * standard. Stamps {@code domain} (the tenant, changelog 230) so the row is scoped on read.
     */
    String INSERT_RETURNING_ID = """
            INSERT INTO backup_history \
            (domain, created_at, requested_by, scope, target, encrypted, status, size_bytes, error, \
             location_ref, verifier_salt, verifier) \
            VALUES (:domain, :created_at, :requested_by, :scope, :target, :encrypted, :status, :size_bytes, \
             :error, :location_ref, :verifier_salt, :verifier) \
            RETURNING id""";

    @Query(INSERT_RETURNING_ID)
    Mono<UUID> insertReturningId(@Param("domain") String domain,
                                 @Param("created_at") Instant createdAt,
                                 @Param("requested_by") String requestedBy,
                                 @Param("scope") String scope,
                                 @Param("target") String target,
                                 @Param("encrypted") boolean encrypted,
                                 @Param("status") String status,
                                 @Param("size_bytes") Long sizeBytes,
                                 @Param("error") String error,
                                 @Param("location_ref") String locationRef,
                                 @Param("verifier_salt") String verifierSalt,
                                 @Param("verifier") String verifier);

    /** Partial UPDATE: set status, and size/location only when the new value is non-null
     *  (COALESCE keep-existing), always overwrite error. */
    String UPDATE_STATUS =
            "UPDATE backup_history SET status = :status, "
            + "size_bytes = COALESCE(:size, size_bytes), "
            + "location_ref = COALESCE(:loc, location_ref), "
            + "error = :error WHERE id = :id";

    @Modifying
    @Query(UPDATE_STATUS)
    Mono<Long> updateStatus(UUID id, String status, Long size, String loc, String error);
}
