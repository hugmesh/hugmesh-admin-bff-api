package net.hugmesh.adminbff.cloudbackup;

import org.springframework.stereotype.Repository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.time.Instant;

/**
 * Reactive (R2DBC) store for {@code backup_artifact} — the per-SERVICE rows under a
 * {@link BackupSet} (schema 162). App-generated {@code varchar(36)} UUID ids; rows are never
 * deleted (status transitions are UPDATEs = audit). The artifact read is BY PARENT SET id —
 * the set's own scoped read ({@link BackupSetRepository#findScoped}) is the tenant gate, so an
 * artifact list is only ever served after the parent set was resolved in scope.
 *
 * <p>Backed by the Spring Data {@link BackupArtifactR2dbcRepository} (no raw
 * {@code DatabaseClient}); maps the {@link BackupArtifactRow} entity to the
 * {@link BackupArtifact} domain record.
 */
@Repository
public class BackupArtifactRepository {

    private final BackupArtifactR2dbcRepository repo;

    public BackupArtifactRepository(BackupArtifactR2dbcRepository repo) {
        this.repo = repo;
    }

    /** Insert a PENDING artifact under a set (app-generated id). Returns the inserted row. */
    public Mono<BackupArtifact> insert(String setId, String service, String kind) {
        Instant createdAt = Instant.now();
        // INSERT omits id (filled from the (gen_random_uuid())::text column DEFAULT, changelog
        // 200) and the not-yet-set size_bytes/completed_at (default NULL); RETURNING id hands back
        // the generated string, mapped into the persisted artifact with the SAME field
        // order/values as before.
        return repo.insertReturningId(setId, service, kind, BackupArtifact.STATUS_PENDING, createdAt)
                .map(genId -> new BackupArtifact(genId, setId, service, kind, null,
                        BackupArtifact.STATUS_PENDING, createdAt, null));
    }

    /** The artifacts under one set (the per-service detail view). Ordered by service. */
    public Flux<BackupArtifact> listForSet(String setId) {
        return repo.findBySetIdOrderByService(setId).map(BackupArtifactRow::toDomain);
    }

    /** Mark an artifact's terminal status + size (the effector's per-service completion
     *  write). Returns rows-updated. */
    public Mono<Long> markStatus(String id, String status, Long sizeBytes) {
        return repo.markStatus(id, status, sizeBytes);
    }
}
