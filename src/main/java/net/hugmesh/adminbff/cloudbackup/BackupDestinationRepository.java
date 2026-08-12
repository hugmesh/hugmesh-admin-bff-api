package net.hugmesh.adminbff.cloudbackup;

import org.springframework.stereotype.Repository;
import reactor.core.publisher.Mono;

import java.time.Instant;

/**
 * Reactive (R2DBC) store for {@code backup_destination} — the per-domain destination CONFIG
 * (schema 160). At most one row per brand (UNIQUE on {@code domain}); {@link #upsert} writes
 * an INSERT-or-UPDATE keyed on the stamped {@code domain} (never the caller). The read is
 * SCOPED: a scoped admin sees ONLY their own brand's config; a SUPERADMIN read is BY EXPLICIT
 * domain (the superadmin always targets a brand by path/argument).
 *
 * <p>{@code secretRef} / {@code destinationRef} are REFERENCES only — never credential bytes.
 *
 * <p>Backed by the Spring Data {@link BackupDestinationR2dbcRepository} (no raw
 * {@code DatabaseClient}); maps the {@link BackupDestinationRow} entity to the
 * {@link BackupDestination} domain record.
 */
@Repository
public class BackupDestinationRepository {

    private final BackupDestinationR2dbcRepository repo;

    public BackupDestinationRepository(BackupDestinationR2dbcRepository repo) {
        this.repo = repo;
    }

    /** INSERT a new destination row, returning the generated id mapped to a domain record. */
    private Mono<BackupDestination> insertDestination(BackupDestinationKind kind, String destinationRef,
                                                      String secretRef, String domain, String updatedBy) {
        Instant createdAt = Instant.now();
        // INSERT omits id (filled from the (gen_random_uuid())::text column DEFAULT,
        // changelog 200) and the not-yet-set updated_at (default NULL); RETURNING id
        // hands back the generated string, mapped into the persisted destination with
        // the SAME field order/values as before.
        return repo.insertReturningId(kind.wire(), destinationRef, secretRef, domain, updatedBy, createdAt)
                .map(genId -> new BackupDestination(genId, kind, destinationRef, secretRef,
                        domain, updatedBy, createdAt, null));
    }

    /** The destination config for one explicit brand, or empty when unconfigured. */
    public Mono<BackupDestination> findByDomain(String domain) {
        return repo.findByDomain(domain).map(BackupDestinationRow::toDomain);
    }

    /**
     * Upsert the per-domain destination config (the PUT). The {@code domain} is the stamped
     * tenant (never the caller); an existing row for the brand is UPDATEd in place (UNIQUE on
     * domain), else a fresh row is INSERTed. Returns the resulting row.
     */
    public Mono<BackupDestination> upsert(BackupDestinationKind kind, String destinationRef,
                                          String secretRef, String domain, String updatedBy) {
        return repo.findByDomain(domain)
                .flatMap(existing -> repo.updateByDomain(kind.wire(), destinationRef, secretRef,
                                updatedBy, domain)
                        .then(repo.findByDomain(domain).map(BackupDestinationRow::toDomain)))
                // No existing row: insert and return the newly created destination.
                .switchIfEmpty(Mono.defer(() -> insertDestination(kind, destinationRef, secretRef, domain, updatedBy)));
    }
}
