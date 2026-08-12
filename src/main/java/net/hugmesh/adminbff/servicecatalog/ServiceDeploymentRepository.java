package net.hugmesh.adminbff.servicecatalog;

import org.springframework.stereotype.Repository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import net.hugmesh.commons.security.PrincipalDomain;

import java.time.Instant;

/**
 * Reactive (R2DBC) store for {@code service_deployment} — the per-domain LIFECYCLE
 * accounting table (schema in Liquibase {@code db/changelog/102-service-deployment.xml}).
 * App-generated {@code varchar(36)} UUID ids, never a blocking call.
 *
 * <p>Backed by the Spring Data {@link ServiceDeploymentR2dbcRepository} (no raw
 * {@code DatabaseClient}); maps the {@link ServiceDeploymentRow} entity to/from the
 * {@link ServiceDeployment} domain record.
 *
 * <p>The loop NEVER deletes a row — a deployment ends via a CAS {@code active -> ended}
 * ({@link #markEnded}) so the table stays the audit trail. {@code ending_at} is the single
 * expiry clock; {@link #dueForEnding} is the expiry working set the
 * {@code ServiceDeploymentExpiryAction} scans.
 *
 * <p>DOMAIN ISOLATION:
 * <ul>
 *   <li>the SUPERADMIN create/read surface ({@link #insertActive}, {@link #findByDomain})
 *       targets an EXPLICIT {@code domain} argument; NEVER read from a request body.</li>
 *   <li>the brand-ADMIN / scoped read surface ({@link #listForScope}) is pinned to the
 *       caller's own {@link PrincipalDomain}; a SUPERADMIN scope sees every brand's rows.</li>
 *   <li>the expiry working set ({@link #dueForEnding}) is UNSCOPED — the single-writer
 *       reconcile loop drives every brand's effectors (the 008 convention).</li>
 * </ul>
 */
@Repository
public class ServiceDeploymentRepository {

    private final ServiceDeploymentR2dbcRepository repo;

    public ServiceDeploymentRepository(ServiceDeploymentR2dbcRepository repo) {
        this.repo = repo;
    }

    /**
     * Insert a new ACTIVE deployment (app-generated id) FOR an explicit {@code domain},
     * recording {@code created_at} (now), the {@code ending_at} expiry clock (null =
     * no-expiry), the opaque {@code enforce_actions} list, and {@code created_by_subject}.
     * Returns the persisted row.
     */
    public Mono<ServiceDeployment> insertActive(String domain, String serviceKey, String profileRef,
                                                Instant endingAt, String enforceActions,
                                                String createdBySubject) {
        Instant now = Instant.now();
        // INSERT omits id (filled from the (gen_random_uuid())::text column DEFAULT, changelog
        // 200) and the not-yet-set ended_at (default NULL); RETURNING id hands back the generated
        // string, mapped into the persisted ServiceDeployment with the SAME field order/values.
        return repo.insertReturningId(domain, serviceKey, profileRef,
                        ServiceDeployment.STATE_ACTIVE, now, endingAt, enforceActions,
                        ServiceDeployment.PROP_PENDING, createdBySubject)
                .map(genId -> new ServiceDeployment(genId, domain, serviceKey, profileRef,
                        ServiceDeployment.STATE_ACTIVE, now, endingAt, enforceActions,
                        ServiceDeployment.PROP_PENDING, null, createdBySubject));
    }

    /** One deployment by id (UNSCOPED) — the expiry loop / get-by-id lookup. */
    public Mono<ServiceDeployment> findById(String id) {
        return repo.findById(id).map(ServiceDeploymentRow::toDomain);
    }

    /** Every deployment for an EXPLICIT {@code domain} (the superadmin per-domain list),
     *  newest first. */
    public Flux<ServiceDeployment> findByDomain(String domain) {
        return repo.findByDomainOrderByCreatedAtDesc(domain).map(ServiceDeploymentRow::toDomain);
    }

    /**
     * Every deployment VISIBLE to the given tenant scope — the list surface. A scoped
     * principal sees ONLY their own brand's rows; a SUPERADMIN scope sees every brand's rows.
     * Fail-closed: a null scope is treated as scoped to the NO_DOMAIN sentinel (matches
     * nothing).
     */
    public Flux<ServiceDeployment> listForScope(PrincipalDomain scope) {
        if (scope == null || scope.scoped()) {
            String domain = scope == null ? PrincipalDomain.NO_DOMAIN : scope.domain();
            return repo.findByDomainOrderByCreatedAtDesc(domain).map(ServiceDeploymentRow::toDomain);
        }
        return repo.findByOrderByDomainAscCreatedAtDesc().map(ServiceDeploymentRow::toDomain);
    }

    /**
     * The expiry working set: ACTIVE deployments whose {@code ending_at} clock has passed.
     * No-expiry (ending_at NULL) rows are excluded. UNSCOPED — the single-writer loop drives
     * every brand. Ordered by the clock.
     */
    public Flux<ServiceDeployment> dueForEnding(Instant now) {
        return repo.dueForEnding(now).map(ServiceDeploymentRow::toDomain);
    }

    /**
     * Compare-and-swap {@code active -> ended} for one row id, guarded on the current state
     * so only ONE writer wins the transition (returns the rows-updated count: 1 = this caller
     * won, 0 = already ended by another tick/replica). Stamps {@code ended_at = now()}.
     */
    public Mono<Long> markEnded(String id) {
        return repo.markEnded(id);
    }

    /** Record the enforce-actions leg outcome (pending/applied/failed) for a row. */
    public Mono<Long> updatePropagationState(String id, String propagationState) {
        return repo.updatePropagationState(id, propagationState);
    }
}
