package net.hugmesh.adminbff.cloudbackup;

import org.springframework.data.r2dbc.repository.Modifying;
import org.springframework.data.r2dbc.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import reactor.core.publisher.Mono;

import java.time.Instant;

/**
 * Reactive (R2DBC) Spring Data store for {@code backup_destination} (changeset 160). The
 * per-domain read is a derived finder; the partial-column UPDATE that the upsert uses for an
 * existing row is a {@code @Query} static-final constant (a partial UPDATE stamping
 * {@code updated_at = now()} is not derivable). The {@link BackupDestinationRepository} facade
 * maps rows to/from the {@link BackupDestination} domain record and composes the read-then
 * insert-or-update upsert.
 */
public interface BackupDestinationR2dbcRepository
        extends ReactiveCrudRepository<BackupDestinationRow, String> {

    /**
     * Insert a fresh per-domain destination row with a DB-generated id (changelog 200) — the
     * upsert's INSERT branch: {@code id} is OMITTED → filled from the {@code
     * (gen_random_uuid())::text} column DEFAULT; {@code RETURNING id} reads the generated
     * varchar(36) back ({@code Mono<String>}). The not-yet-set {@code updated_at} is OMITTED
     * (default NULL — the fresh-row shape). Columns match the {@link BackupDestinationRow} order
     * (id + updated_at excluded). The UPDATE branch ({@link #updateByDomain}) is unchanged.
     */
    String INSERT_RETURNING_ID = """
            INSERT INTO backup_destination \
            (kind, destination_ref, secret_ref, domain, updated_by, created_at) \
            VALUES (:kind, :destinationRef, :secretRef, :domain, :updatedBy, :createdAt) \
            RETURNING id""";

    @Query(INSERT_RETURNING_ID)
    Mono<String> insertReturningId(@Param("kind") String kind,
                                   @Param("destinationRef") String destinationRef,
                                   @Param("secretRef") String secretRef,
                                   @Param("domain") String domain,
                                   @Param("updatedBy") String updatedBy,
                                   @Param("createdAt") Instant createdAt);

    /** The destination config for one explicit brand, or empty when unconfigured. */
    Mono<BackupDestinationRow> findByDomain(String domain);

    /** UPDATE the existing per-domain row in place, stamping {@code updated_at}. */
    String UPDATE_BY_DOMAIN =
            "UPDATE backup_destination SET kind = :kind, destination_ref = :destinationRef, "
            + "secret_ref = :secretRef, updated_by = :updatedBy, updated_at = now() "
            + "WHERE domain = :domain";

    @Modifying
    @Query(UPDATE_BY_DOMAIN)
    Mono<Long> updateByDomain(String kind, String destinationRef, String secretRef,
                              String updatedBy, String domain);
}
