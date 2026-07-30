package systems.hugmesh.adminbff.backup;

import org.springframework.stereotype.Repository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import systems.hugmesh.commons.security.PrincipalDomain;

import java.time.Instant;
import java.util.UUID;

/**
 * Reactive (R2DBC) store for {@code backup_history} (Liquibase changeset 050).
 *
 * <p>Backed by the Spring Data {@link BackupHistoryRowRepository} (no raw
 * {@code DatabaseClient}); maps the {@link BackupHistoryRow} entity to the
 * {@link BackupRecord} JSON projection. IDs are DB-GENERATED — the {@code id} column
 * carries a {@code gen_random_uuid()} DEFAULT (pgcrypto, changelog 200), so the INSERT
 * omits {@code id} and reads the generated UUID back via {@code RETURNING id} (the app no
 * longer mints {@code UUID.randomUUID()}). The INSERT stamps {@code created_at} now
 * (the prior {@code now()} server default) and starts {@code QUEUED}; the status
 * transition uses the COALESCE partial UPDATE so unset size/location keep their value.
 */
@Repository
public class BackupRepository {

    private final BackupHistoryRowRepository repo;

    public BackupRepository(BackupHistoryRowRepository repo) {
        this.repo = repo;
    }

    /**
     * Newest-first history for the admin Backups view, SCOPED to the caller's tenant:
     * a brand-scoped ADMIN sees only their brand's rows; SUPERADMIN (unscoped) sees all.
     * Mirrors the {@code AccessSuspensionRepository} scope idiom (fail-closed to
     * {@code NO_DOMAIN} when the scope is unresolvable).
     */
    public Flux<BackupRecord> list(PrincipalDomain scope) {
        if (scope == null || scope.scoped()) {
            String domain = scope == null ? PrincipalDomain.NO_DOMAIN : scope.domain();
            return repo.findByDomainOrderByCreatedAtDesc(domain).map(BackupHistoryRow::toRecord);
        }
        return repo.findAllByOrderByCreatedAtDesc().map(BackupHistoryRow::toRecord);
    }

    /** A single backup VISIBLE to the caller's tenant — used for detail + restore-source
     *  resolution, so a brand-X admin cannot resolve (and restore from) brand-Y's backup. */
    public Mono<BackupRecord> find(String id, PrincipalDomain scope) {
        UUID uuid = UUID.fromString(id);
        if (scope == null || scope.scoped()) {
            String domain = scope == null ? PrincipalDomain.NO_DOMAIN : scope.domain();
            return repo.findByIdAndDomain(uuid, domain).map(BackupHistoryRow::toRecord);
        }
        return repo.findById(uuid).map(BackupHistoryRow::toRecord);
    }

    /**
     * Insert a freshly-queued backup row (DB-generated id) and return it. The plaintext
     * password is NEVER passed here. Stamps the caller's tenant {@code domain} (scoped
     * admin → their brand; SUPERADMIN/unresolvable → {@code 'default'}) so the row is
     * scoped on subsequent reads.
     */
    public Mono<BackupRecord> insert(String requestedBy, String scope, String target,
                                     boolean encrypted, String verifierSalt, String verifier,
                                     PrincipalDomain tenantScope) {
        Instant createdAt = Instant.now();
        String domain = (tenantScope != null && tenantScope.scoped()) ? tenantScope.domain() : "default";
        return repo.insertReturningId(domain, createdAt, requestedBy, scope, target, encrypted,
                        "QUEUED", null, null, null, verifierSalt, verifier)
                .flatMap(genId -> repo.findById(genId).map(BackupHistoryRow::toRecord));
    }

    /** Move a row to a terminal/intermediate status (+ optional size/location/error). */
    public Mono<Void> updateStatus(String id, String status, Long sizeBytes, String locationRef, String error) {
        return repo.updateStatus(UUID.fromString(id), status, sizeBytes, locationRef, error).then();
    }
}
