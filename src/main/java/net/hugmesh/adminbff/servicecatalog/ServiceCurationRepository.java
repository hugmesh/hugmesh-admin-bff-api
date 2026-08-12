package net.hugmesh.adminbff.servicecatalog;

import org.springframework.stereotype.Repository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import net.hugmesh.commons.security.PrincipalDomain;

import java.time.Instant;

/**
 * Reactive (R2DBC) store for {@code service_curation} — the per-domain TWO-TIER offered
 * catalog (schema in Liquibase {@code db/changelog/100-service-curation.xml}). App-generated
 * {@code varchar(36)} UUID ids, never a blocking call.
 *
 * <p>Backed by the Spring Data {@link ServiceCurationR2dbcRepository} (no raw
 * {@code DatabaseClient}); maps the {@link ServiceCurationRow} entity to/from the
 * {@link ServiceCuration} domain record.
 *
 * <p>The catalog is DESIRED-STATE: a withdrawal is a CAS {@code offered -> withdrawn}
 * ({@link #markWithdrawn}) so the row stays the audit trail.
 *
 * <p>DOMAIN ISOLATION — the two tiers:
 * <ul>
 *   <li>the SUPERADMIN write/read surface ({@link #insertOffered}, {@link #findOffered},
 *       {@link #findByDomain}) targets an EXPLICIT {@code domain} argument; NEVER read from a
 *       request body.</li>
 *   <li>the brand-ADMIN read surface ({@link #offeredForScope}) is pinned to the caller's
 *       own {@link PrincipalDomain}; a SUPERADMIN scope reads every brand's rows.</li>
 * </ul>
 */
@Repository
public class ServiceCurationRepository {

    private final ServiceCurationR2dbcRepository repo;

    public ServiceCurationRepository(ServiceCurationR2dbcRepository repo) {
        this.repo = repo;
    }

    /**
     * Insert a new OFFERED row (app-generated id) FOR an explicit {@code domain}, returning
     * it. The caller (superadmin) is expected to have checked for an existing offered row
     * first; the partial unique index is the backstop against a race.
     */
    public Mono<ServiceCuration> insertOffered(String domain, String serviceKey,
                                               String curatedBySubject) {
        Instant now = Instant.now();
        // INSERT omits id (filled from the (gen_random_uuid())::text column DEFAULT, changelog
        // 200); RETURNING id hands back the generated string, mapped into the persisted
        // ServiceCuration with the SAME field order/values as before.
        return repo.insertReturningId(domain, serviceKey, ServiceCuration.STATE_OFFERED,
                        curatedBySubject, now, now)
                .map(genId -> new ServiceCuration(genId, domain, serviceKey,
                        ServiceCuration.STATE_OFFERED, curatedBySubject, now, now));
    }

    /**
     * The OFFERED row for an EXPLICIT (domain, service_key), if any — the superadmin
     * idempotency check (offer-before-offer) and the target of a withdraw.
     */
    public Mono<ServiceCuration> findOffered(String domain, String serviceKey) {
        return repo.findByDomainAndServiceKeyAndState(domain, serviceKey,
                        ServiceCuration.STATE_OFFERED)
                .map(ServiceCurationRow::toDomain);
    }

    /** Every curation row for an EXPLICIT {@code domain} (offered + withdrawn) — the
     *  superadmin per-domain catalog view. Ordered by service_key. */
    public Flux<ServiceCuration> findByDomain(String domain) {
        return repo.findByDomainOrderByServiceKeyAscCreatedAtAsc(domain)
                .map(ServiceCurationRow::toDomain);
    }

    /**
     * The OFFERED catalog VISIBLE to the given tenant scope — the brand-ADMIN read surface
     * ({@code /bff/admin/service-store}). A scoped admin sees ONLY their own brand's offered
     * rows; a SUPERADMIN scope sees every brand's offered rows. Fail-closed: a null scope is
     * treated as scoped to the NO_DOMAIN sentinel (matches nothing).
     */
    public Flux<ServiceCuration> offeredForScope(PrincipalDomain scope) {
        if (scope == null || scope.scoped()) {
            String domain = scope == null ? PrincipalDomain.NO_DOMAIN : scope.domain();
            return repo.findByStateAndDomainOrderByServiceKey(ServiceCuration.STATE_OFFERED, domain)
                    .map(ServiceCurationRow::toDomain);
        }
        return repo.findByStateOrderByDomainAscServiceKeyAsc(ServiceCuration.STATE_OFFERED)
                .map(ServiceCurationRow::toDomain);
    }

    /**
     * Compare-and-swap {@code offered -> withdrawn} for one row id, guarded on the current
     * state so only ONE writer wins the transition (returns the rows-updated count: 1 = this
     * caller won, 0 = already withdrawn). Bumps {@code updated_at}.
     */
    public Mono<Long> markWithdrawn(String id) {
        return repo.markWithdrawn(id);
    }
}
