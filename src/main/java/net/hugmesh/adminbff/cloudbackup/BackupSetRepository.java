package net.hugmesh.adminbff.cloudbackup;

import org.springframework.stereotype.Repository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import net.hugmesh.commons.security.PrincipalDomain;

import java.time.Instant;
import java.util.List;
import java.util.stream.Collectors;

/**
 * Reactive (R2DBC) store for {@code backup_set} — the versioned per-domain + total-cloud
 * backup catalog (schema 160). App-generated {@code varchar(36)} UUID ids, the verified
 * {@code scope == null || scope.scoped() ? WHERE domain=:domain : unscoped} read branch (a
 * scoped ADMIN sees ONLY their brand; SUPERADMIN unscoped), status transitions as UPDATEs, and
 * rows NEVER deleted (the version chain is the history/audit).
 *
 * <p>Backed by the Spring Data {@link BackupSetR2dbcRepository} (no raw {@code DatabaseClient});
 * maps the {@link BackupSetRow} entity to/from the {@link BackupSet} domain record.
 *
 * <h3>Versioning</h3>
 * {@link #maxVersion(String, String)} returns {@code MAX(version)} within a
 * {@code (domain, set_key)} (the device-license {@code maxGeneration} idiom); the service
 * computes the next version before insert, the PG UNIQUE on {@code (domain,set_key,version)} is
 * the backstop. {@link #versions(String, PrincipalDomain)} lists the chain for a set's
 * {@code set_key} (the version-history endpoint).
 */
@Repository
public class BackupSetRepository {

    private final BackupSetR2dbcRepository repo;

    public BackupSetRepository(BackupSetR2dbcRepository repo) {
        this.repo = repo;
    }

    // ── insert (app-UUID id, version pre-allocated by the service) ───────────────────────

    /**
     * Insert a new PENDING backup set (app-generated id) at the given monotonic version. The
     * {@code services} list is stored as a comma-joined string (a portable text encoding of
     * the per-service menu selection). Returns the inserted row.
     */
    public Mono<BackupSet> insert(String setKey, long version, BackupCloudScope scope, String domain,
                                  String createdBy, List<String> services,
                                  BackupDestinationKind destinationKind, String destinationRef,
                                  String encryptionMeta) {
        String joined = joinServices(services);
        String em = encryptionMeta == null ? "" : encryptionMeta;
        Instant createdAt = Instant.now();
        // INSERT omits id (filled from the (gen_random_uuid())::text column DEFAULT, changelog
        // 200) and the not-yet-set size_bytes/started_at/completed_at (default NULL); RETURNING id
        // hands back the generated string, mapped into the persisted BackupSet with the SAME field
        // order/values as before (services round-tripped through the same comma-text encoding).
        return repo.insertReturningId(setKey, version, scope.wire(), domain, createdBy, joined,
                        destinationKind.wire(), destinationRef, em, BackupSet.STATUS_PENDING,
                        createdAt)
                .map(genId -> new BackupSet(genId, setKey, version, scope, domain, createdBy,
                        BackupSetRow.splitServices(joined), destinationKind, destinationRef, null,
                        em, BackupSet.STATUS_PENDING, createdAt, null, null));
    }

    // ── read (admin surface, scoped) ─────────────────────────────────────────────────────

    /** ALL sets VISIBLE to the given tenant scope — the ADMIN list surface (own brand;
     *  SUPERADMIN all). Newest first. */
    public Flux<BackupSet> list(PrincipalDomain scope) {
        if (scope == null || scope.scoped()) {
            String domain = scope == null ? PrincipalDomain.NO_DOMAIN : scope.domain();
            return repo.findByDomainOrderByCreatedAtDesc(domain).map(BackupSetRow::toDomain);
        }
        return repo.findByOrderByCreatedAtDesc().map(BackupSetRow::toDomain);
    }

    /** Sets for ONE explicit brand — the SUPERADMIN cross-domain filter (a superadmin may
     *  filter the unscoped list to a single brand). Newest first. */
    public Flux<BackupSet> listForDomain(String domain) {
        return repo.findByDomainOrderByCreatedAtDesc(domain).map(BackupSetRow::toDomain);
    }

    /** A single row by id, SCOPED to the caller's tenant (a scoped admin can only see their
     *  own brand's row; SUPERADMIN any). Empty when absent OR out of scope (fail-closed). */
    public Mono<BackupSet> findScoped(String id, PrincipalDomain scope) {
        if (scope == null || scope.scoped()) {
            String domain = scope == null ? PrincipalDomain.NO_DOMAIN : scope.domain();
            return repo.findByIdAndDomain(id, domain).map(BackupSetRow::toDomain);
        }
        return repo.findById(id).map(BackupSetRow::toDomain);
    }

    /** A single row by id, UNSCOPED (for internal reconcile/effector reads after authz has
     *  already happened upstream). */
    public Mono<BackupSet> findById(String id) {
        return repo.findById(id).map(BackupSetRow::toDomain);
    }

    /** The version CHAIN for the set identified by {@code id}'s {@code set_key}, SCOPED to the
     *  caller — the version-history endpoint. Resolves the set's set_key first (scoped), then
     *  lists every version within that (domain, set_key), newest version first. Empty when the
     *  anchor set is absent OR out of scope. */
    public Flux<BackupSet> versions(String id, PrincipalDomain scope) {
        return findScoped(id, scope).flatMapMany(anchor ->
                repo.findByDomainAndSetKeyOrderByVersionDesc(anchor.domain(), anchor.setKey())
                        .map(BackupSetRow::toDomain));
    }

    /** The current MAX(version) within a {@code (domain, set_key)}; 0 when the chain is empty.
     *  The service allocates the next version as MAX+1 (the maxGeneration idiom). */
    public Mono<Long> maxVersion(String domain, String setKey) {
        return repo.maxVersion(domain, setKey).defaultIfEmpty(0L);
    }

    // ── status transitions (UPDATEs; rows never deleted) ─────────────────────────────────

    /** Mark a set's terminal status + size (the effector's completion write). UNSCOPED — the
     *  effector acts after authz upstream. Returns rows-updated. */
    public Mono<Long> markStatus(String id, String status, Long sizeBytes) {
        return repo.markStatus(id, status, sizeBytes);
    }

    // ── service-list <-> text encoding (portable; not a PG text[]) ───────────────────────

    private static String joinServices(List<String> services) {
        if (services == null || services.isEmpty()) {
            return "";
        }
        return services.stream().filter(s -> s != null && !s.isBlank())
                .map(String::trim).distinct().collect(Collectors.joining(","));
    }
}
