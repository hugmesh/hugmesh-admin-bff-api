package systems.hugmesh.adminbff.cloudbackup;

import org.springframework.data.r2dbc.repository.Modifying;
import org.springframework.data.r2dbc.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.time.Instant;

/**
 * Reactive (R2DBC) Spring Data store for {@code backup_artifact} (changeset 160, band 162).
 * The per-set listing is a derived finder; the terminal-status CASE UPDATE is a
 * {@code @Query} static-final constant (a CASE-on-status stamping UPDATE is not derivable).
 * The {@link BackupArtifactRepository} facade maps rows to/from the {@link BackupArtifact}
 * domain record.
 */
public interface BackupArtifactR2dbcRepository
        extends ReactiveCrudRepository<BackupArtifactRow, String> {

    /**
     * Insert a PENDING artifact with a DB-generated id (changelog 200): {@code id} is OMITTED →
     * filled from the {@code (gen_random_uuid())::text} column DEFAULT; {@code RETURNING id} reads
     * the generated varchar(36) back ({@code Mono<String>}). The not-yet-set {@code size_bytes}/
     * {@code completed_at} are OMITTED (default NULL — the fresh-artifact shape). Columns match the
     * {@link BackupArtifactRow} order (id + size_bytes + completed_at excluded).
     */
    String INSERT_RETURNING_ID = """
            INSERT INTO backup_artifact \
            (set_id, service, kind, status, created_at) \
            VALUES (:setId, :service, :kind, :status, :createdAt) \
            RETURNING id""";

    @Query(INSERT_RETURNING_ID)
    Mono<String> insertReturningId(@Param("setId") String setId,
                                   @Param("service") String service,
                                   @Param("kind") String kind,
                                   @Param("status") String status,
                                   @Param("createdAt") Instant createdAt);

    /** The artifacts under one set (the per-service detail view), ordered by service. */
    Flux<BackupArtifactRow> findBySetIdOrderByService(String setId);

    /**
     * Mark an artifact's status + size, stamping {@code completed_at} for the terminal states.
     * Returns rows-updated.
     */
    String MARK_STATUS =
            "UPDATE backup_artifact SET status = :status, size_bytes = :size, "
            + "completed_at = CASE WHEN :status IN ('complete','failed') THEN now() "
            + "ELSE completed_at END "
            + "WHERE id = :id";

    @Modifying
    @Query(MARK_STATUS)
    Mono<Long> markStatus(String id, String status, Long size);
}
