package systems.hugmesh.adminbff.cloudbackup;

import org.springframework.data.r2dbc.repository.Modifying;
import org.springframework.data.r2dbc.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.time.Instant;

/**
 * Reactive (R2DBC) Spring Data store for {@code backup_set} (changeset 160). The scoped /
 * unscoped lists, the by-id-and-domain scoped read, and the version chain are derived
 * finders; the {@code MAX(version)} aggregate and the CASE-bearing terminal-status UPDATE are
 * {@code @Query} static-final constants (an aggregate and a CASE-on-status stamping UPDATE are
 * not derivable). The {@link BackupSetRepository} facade maps rows to/from the
 * {@link BackupSet} domain record.
 */
public interface BackupSetR2dbcRepository
        extends ReactiveCrudRepository<BackupSetRow, String> {

    /**
     * Insert a new PENDING backup set with a DB-generated id (changelog 200): {@code id} is
     * OMITTED → filled from the {@code (gen_random_uuid())::text} column DEFAULT; {@code RETURNING
     * id} reads the generated varchar(36) back ({@code Mono<String>}). The not-yet-set {@code
     * size_bytes}/{@code started_at}/{@code completed_at} are OMITTED (default NULL — the
     * fresh-set shape). Columns match the {@link BackupSetRow} order (id + those three excluded).
     */
    String INSERT_RETURNING_ID = """
            INSERT INTO backup_set \
            (set_key, version, scope, domain, created_by, services, destination_kind, \
             destination_ref, encryption_meta, status, created_at) \
            VALUES (:setKey, :version, :scope, :domain, :createdBy, :services, :destinationKind, \
             :destinationRef, :encryptionMeta, :status, :createdAt) \
            RETURNING id""";

    @Query(INSERT_RETURNING_ID)
    Mono<String> insertReturningId(@Param("setKey") String setKey,
                                   @Param("version") long version,
                                   @Param("scope") String scope,
                                   @Param("domain") String domain,
                                   @Param("createdBy") String createdBy,
                                   @Param("services") String services,
                                   @Param("destinationKind") String destinationKind,
                                   @Param("destinationRef") String destinationRef,
                                   @Param("encryptionMeta") String encryptionMeta,
                                   @Param("status") String status,
                                   @Param("createdAt") Instant createdAt);

    /** Sets for ONE explicit brand, newest first (the scoped list + superadmin filter). */
    Flux<BackupSetRow> findByDomainOrderByCreatedAtDesc(String domain);

    /** ALL sets, newest first (the unscoped SUPERADMIN list). */
    Flux<BackupSetRow> findByOrderByCreatedAtDesc();

    /** A single row by id, scoped to a brand (fail-closed when out of scope). */
    Mono<BackupSetRow> findByIdAndDomain(String id, String domain);

    /** The version chain within a (domain, set_key), newest version first. */
    Flux<BackupSetRow> findByDomainAndSetKeyOrderByVersionDesc(String domain, String setKey);

    /** The current MAX(version) within a (domain, set_key); 0 when the chain is empty. */
    String MAX_VERSION =
            "SELECT COALESCE(MAX(version), 0) FROM backup_set "
            + "WHERE domain = :domain AND set_key = :setKey";

    @Query(MAX_VERSION)
    Mono<Long> maxVersion(String domain, String setKey);

    /**
     * Mark a set's terminal status + size, stamping {@code completed_at} for the terminal
     * states and {@code started_at} on {@code running}. Returns rows-updated.
     */
    String MARK_STATUS = """
            UPDATE backup_set SET status = :status, size_bytes = :size,
            completed_at = CASE WHEN :status IN ('complete','failed') THEN now()
                                ELSE completed_at END,
            started_at = CASE WHEN :status = 'running' THEN now() ELSE started_at END
            WHERE id = :id
            """;

    @Modifying
    @Query(MARK_STATUS)
    Mono<Long> markStatus(String id, String status, Long size);
}
