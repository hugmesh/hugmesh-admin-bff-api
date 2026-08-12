package net.hugmesh.adminbff.suspension;

import org.springframework.stereotype.Repository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import net.hugmesh.commons.security.PrincipalDomain;

import java.time.Instant;

/**
 * Reactive (R2DBC) store for {@code access_suspension} — the desired-state table
 * the single-writer reconcile loop reads/writes (schema in Liquibase
 * {@code db/changelog/008-access-suspension.xml}).
 *
 * <p>Backed by the Spring Data {@link AccessSuspensionRowRepository} (no raw
 * {@code DatabaseClient}); maps the {@link AccessSuspensionRow} entity to the
 * {@link AccessSuspension} domain record. The loop NEVER deletes a row — a restore is a
 * CAS {@code active -> restored}; {@code insertActive} relies on the partial unique
 * index as the double-ban backstop.
 */
@Repository
public class AccessSuspensionRepository {

    private final AccessSuspensionRowRepository repo;

    public AccessSuspensionRepository(AccessSuspensionRowRepository repo) {
        this.repo = repo;
    }

    /** Insert a new ACTIVE suspension (DB-generated id), returning it. The INSERT omits
     *  {@code id} (filled from the {@code (gen_random_uuid())::text} column DEFAULT, changelog
     *  200) and {@code RETURNING id} hands back the generated string, which we read back by
     *  that id to return the persisted row (same field order/values as before). */
    public Mono<AccessSuspension> insertActive(String casdoorUser, String localpart, String role,
                                               Instant expiresAt, boolean restoreRole,
                                               String reason, String setBy, String domain) {
        return repo.insertReturningId(casdoorUser, localpart, role, AccessSuspension.STATE_ACTIVE,
                        Instant.now(), expiresAt, restoreRole, AccessSuspension.PROP_PENDING,
                        reason, setBy, domain)
                .flatMap(genId -> repo.findById(genId).map(AccessSuspensionRow::toDomain));
    }

    /** The active suspension for a (user, role), if any. UNSCOPED. */
    public Mono<AccessSuspension> findActive(String casdoorUser, String role) {
        return repo.findByCasdoorUserAndRoleAndState(casdoorUser, role, AccessSuspension.STATE_ACTIVE)
                .map(AccessSuspensionRow::toDomain);
    }

    /** The active suspension for a (user, role) VISIBLE to the given tenant scope. */
    public Mono<AccessSuspension> findActive(String casdoorUser, String role, PrincipalDomain scope) {
        if (scope == null || scope.scoped()) {
            String domain = scope == null ? PrincipalDomain.NO_DOMAIN : scope.domain();
            return repo.findByCasdoorUserAndRoleAndStateAndDomain(
                            casdoorUser, role, AccessSuspension.STATE_ACTIVE, domain)
                    .map(AccessSuspensionRow::toDomain);
        }
        return findActive(casdoorUser, role);
    }

    /** All ACTIVE suspensions for a given role (the loop's MINUS set). */
    public Flux<AccessSuspension> activeByRole(String role) {
        return repo.findByRoleAndStateOrderByCasdoorUser(role, AccessSuspension.STATE_ACTIVE)
                .map(AccessSuspensionRow::toDomain);
    }

    /** Any ACTIVE suspension on a localpart for a platform role (the broker guard). */
    public Flux<AccessSuspension> activeByLocalpartAndRole(String localpart, String role) {
        return repo.findByLocalpartAndRoleAndState(localpart, role, AccessSuspension.STATE_ACTIVE)
                .map(AccessSuspensionRow::toDomain);
    }

    /** Every ACTIVE suspension on a localpart (any role, any brand), widest-impact first. */
    public Flux<AccessSuspension> activeByLocalpart(String localpart) {
        return repo.activeByLocalpart(localpart).map(AccessSuspensionRow::toDomain);
    }

    /** All ACTIVE suspensions (every role, every brand) — the full reconcile working set. */
    public Flux<AccessSuspension> allActive() {
        return repo.findByStateOrderByRoleAscCasdoorUserAsc(AccessSuspension.STATE_ACTIVE)
                .map(AccessSuspensionRow::toDomain);
    }

    /** All ACTIVE suspensions VISIBLE to the given tenant scope — the ADMIN read surface. */
    public Flux<AccessSuspension> allActive(PrincipalDomain scope) {
        if (scope == null || scope.scoped()) {
            String domain = scope == null ? PrincipalDomain.NO_DOMAIN : scope.domain();
            return repo.findByStateAndDomainOrderByRoleAscCasdoorUserAsc(
                            AccessSuspension.STATE_ACTIVE, domain)
                    .map(AccessSuspensionRow::toDomain);
        }
        return allActive();
    }

    /** The expiry working set: timed ACTIVE suspensions whose TTL has passed + restorable. */
    public Flux<AccessSuspension> dueForRestore(Instant now) {
        return repo
                .findByStateAndRestoreRoleTrueAndExpiresAtIsNotNullAndExpiresAtLessThanEqualOrderByExpiresAt(
                        AccessSuspension.STATE_ACTIVE, now)
                .map(AccessSuspensionRow::toDomain);
    }

    /** CAS {@code active -> restored} for one row id (1 = won, 0 = already restored). */
    public Mono<Long> markRestored(String id) {
        return repo.markRestored(id);
    }

    /** Record the homeserver-leg outcome (pending/applied/failed) for a row. */
    public Mono<Long> updatePropagationState(String id, String propagationState) {
        return repo.updatePropagationState(id, propagationState);
    }
}
