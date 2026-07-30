package systems.hugmesh.adminbff.servicecatalog.scaffold;

import org.springframework.stereotype.Repository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.time.Instant;

/**
 * Reactive (R2DBC) store for {@code service_scaffold} — the per-domain scaffold-request table
 * (schema in Liquibase {@code db/changelog/320-service-scaffold.xml}). DB-generated
 * {@code varchar(36)} UUID ids, never a blocking call.
 *
 * <p>Backed by the Spring Data {@link ServiceScaffoldR2dbcRepository}; maps the
 * {@link ServiceScaffoldRow} entity to/from the {@link ServiceScaffold} domain record.
 *
 * <p>The surface never deletes a row — a scaffold is materialised via a CAS
 * {@code requested -> archived} ({@link #markArchived}) so the table stays the audit trail. The
 * superadmin create/read/archive surface targets an EXPLICIT {@code domain} argument; it is never
 * read from a request body.
 */
@Repository
public class ServiceScaffoldRepository {

    private final ServiceScaffoldR2dbcRepository repo;

    public ServiceScaffoldRepository(ServiceScaffoldR2dbcRepository repo) {
        this.repo = repo;
    }

    /**
     * Insert a new {@code requested} scaffold (DB-generated id) FOR an explicit {@code domain},
     * stamping {@code created_at}/{@code updated_at} (now) and the superadmin subject. Returns the
     * persisted row.
     */
    public Mono<ServiceScaffold> insertRequested(String domain, String serviceKey, String archetype,
                                                 String displayName, String mountAt, String requiresRole,
                                                 String createdBySubject) {
        Instant now = Instant.now();
        return repo.insertReturningId(domain, serviceKey, archetype, displayName, mountAt, requiresRole,
                        ServiceScaffold.STATE_REQUESTED, createdBySubject, now, now)
                .map(genId -> new ServiceScaffold(genId, domain, serviceKey, archetype, displayName,
                        mountAt, requiresRole, ServiceScaffold.STATE_REQUESTED, createdBySubject, now, now));
    }

    /** One scaffold by id (UNSCOPED) — the archive lookup (the caller domain-guards it). */
    public Mono<ServiceScaffold> findById(String id) {
        return repo.findById(id).map(ServiceScaffoldRow::toDomain);
    }

    /** Every scaffold for an EXPLICIT {@code domain} (the superadmin per-domain view), newest first. */
    public Flux<ServiceScaffold> findByDomain(String domain) {
        return repo.findByDomainOrderByCreatedAtDesc(domain).map(ServiceScaffoldRow::toDomain);
    }

    /**
     * CAS {@code requested -> archived} for one id, stamping {@code updated_at}. Returns the
     * rows-updated count (1 = this caller materialised it first, 0 = already archived) so the
     * archive endpoint stays idempotent (a re-download is a pure read).
     */
    public Mono<Long> markArchived(String id) {
        return repo.markArchived(id);
    }
}
