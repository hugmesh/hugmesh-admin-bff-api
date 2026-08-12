package net.hugmesh.adminbff.domainlock;

import org.springframework.stereotype.Repository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import net.hugmesh.commons.security.PrincipalDomain;

import java.time.Instant;

/**
 * Reactive (R2DBC) store for {@code domain_lock} — the ADD-active desired-state table
 * the single-writer DOMAIN-LOCK reconcile loop reads/writes (schema in Liquibase
 * {@code db/changelog/009-domain-lock.xml}).
 *
 * <p>Backed by the Spring Data {@link DomainLockRowRepository} (no raw
 * {@code DatabaseClient}); maps the {@link DomainLockRow} entity to the {@link DomainLock}
 * domain record. The loop NEVER deletes a row — an unlock is a CAS {@code active ->
 * removed}; {@code insertActive} relies on the partial unique index as the backstop.
 */
@Repository
public class DomainLockRepository {

    private final DomainLockRowRepository repo;

    public DomainLockRepository(DomainLockRowRepository repo) {
        this.repo = repo;
    }

    /** Insert a new ACTIVE domain lock (DB-generated id), returning it. The INSERT omits
     *  {@code id} (filled from the {@code (gen_random_uuid())::text} column DEFAULT, changelog
     *  200) and {@code RETURNING id} hands back the generated string, which we read back by
     *  that id to return the persisted row (same field order/values as before). */
    public Mono<DomainLock> insertActive(String casdoorUser, String localpart, String role,
                                         String reason, String setBy, String domain) {
        return repo.insertReturningId(casdoorUser, localpart, role, DomainLock.STATE_ACTIVE,
                        Instant.now(), DomainLock.PROP_PENDING, reason, setBy, domain)
                .flatMap(genId -> repo.findById(genId).map(DomainLockRow::toDomain));
    }

    /** The active lock for a (user, role), if any. UNSCOPED. */
    public Mono<DomainLock> findActive(String casdoorUser, String role) {
        return repo.findByCasdoorUserAndRoleAndState(casdoorUser, role, DomainLock.STATE_ACTIVE)
                .map(DomainLockRow::toDomain);
    }

    /** The active lock for a (user, role) VISIBLE to the given tenant scope. */
    public Mono<DomainLock> findActive(String casdoorUser, String role, PrincipalDomain scope) {
        if (scope == null || scope.scoped()) {
            String domain = scope == null ? PrincipalDomain.NO_DOMAIN : scope.domain();
            return repo.findByCasdoorUserAndRoleAndStateAndDomain(
                            casdoorUser, role, DomainLock.STATE_ACTIVE, domain)
                    .map(DomainLockRow::toDomain);
        }
        return findActive(casdoorUser, role);
    }

    /** All ACTIVE locks for a given role — the loop's desired set + the force-local allowlist. */
    public Flux<DomainLock> activeByRole(String role) {
        return repo.findByRoleAndStateOrderByCasdoorUser(role, DomainLock.STATE_ACTIVE)
                .map(DomainLockRow::toDomain);
    }

    /** Any ACTIVE lock on a localpart for a platform role (a force-local guard). */
    public Flux<DomainLock> activeByLocalpartAndRole(String localpart, String role) {
        return repo.findByLocalpartAndRoleAndState(localpart, role, DomainLock.STATE_ACTIVE)
                .map(DomainLockRow::toDomain);
    }

    /** All ACTIVE locks (every role, every brand) — the full working set. UNSCOPED. */
    public Flux<DomainLock> allActive() {
        return repo.findByStateOrderByRoleAscCasdoorUserAsc(DomainLock.STATE_ACTIVE)
                .map(DomainLockRow::toDomain);
    }

    /** All ACTIVE locks VISIBLE to the given tenant scope — the ADMIN read surface. */
    public Flux<DomainLock> allActive(PrincipalDomain scope) {
        if (scope == null || scope.scoped()) {
            String domain = scope == null ? PrincipalDomain.NO_DOMAIN : scope.domain();
            return repo.findByStateAndDomainOrderByRoleAscCasdoorUserAsc(DomainLock.STATE_ACTIVE, domain)
                    .map(DomainLockRow::toDomain);
        }
        return allActive();
    }

    /** CAS {@code active -> removed} for one row id (1 = won, 0 = already removed). */
    public Mono<Long> markRemoved(String id) {
        return repo.markRemoved(id);
    }

    /** Record the force-local-leg outcome (pending/applied/failed/degraded) for a row. */
    public Mono<Long> updatePropagationState(String id, String propagationState) {
        return repo.updatePropagationState(id, propagationState);
    }
}
