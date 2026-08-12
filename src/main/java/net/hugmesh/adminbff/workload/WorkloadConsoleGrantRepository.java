package net.hugmesh.adminbff.workload;

import org.springframework.stereotype.Repository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import net.hugmesh.commons.security.PrincipalDomain;

import java.time.Instant;

/**
 * Reactive (R2DBC) store for {@code workload_console_grant} (schema in Liquibase
 * {@code db/changelog/110-workload-console-grants.xml}). App-generated UUID ids, the
 * {@code findActive}-before-insert idempotency (the partial unique index is the Postgres
 * backstop; H2 relies on the service guard), the CAS {@code active -> revoked}/{@code expired}
 * that NEVER deletes, the monotonic {@code generation} bump on mutate, and the verified
 * {@code scope == null || scope.scoped() ? WHERE domain=:domain : unscoped} branch for the read
 * surface.
 *
 * <p>Backed by the Spring Data {@link WorkloadConsoleGrantR2dbcRepository} (no raw
 * {@code DatabaseClient}); maps the {@link WorkloadConsoleGrantRow} entity to/from the
 * {@link WorkloadConsoleGrant} domain record.
 */
@Repository
public class WorkloadConsoleGrantRepository {

    private final WorkloadConsoleGrantR2dbcRepository repo;

    public WorkloadConsoleGrantRepository(WorkloadConsoleGrantR2dbcRepository repo) {
        this.repo = repo;
    }

    // ── the authz-predicate read (the HOT path, PRIMARY = read-your-writes) ──────

    /** The active, in-TTL grant for (grantee, targetDomain), if any — the
     *  {@link WorkloadAuthorizationFilter} STEP-6 lookup. UNSCOPED by domain (the predicate
     *  passes the issuer-derived domain as {@code targetDomain} itself); the SQL filters on
     *  state='active' only, the caller checks {@code isLiveAt(now)} for the TTL. */
    public Mono<WorkloadConsoleGrant> findActive(String grantee, String targetDomain) {
        return repo.findByGranteeAndTargetDomainAndState(grantee, targetDomain,
                        WorkloadConsoleGrant.STATE_ACTIVE)
                .map(WorkloadConsoleGrantRow::toDomain);
    }

    // ── grant (findActive-then-insert idempotency) ──────────────────────────────

    /** Insert a new ACTIVE READ_ONLY grant (app-generated id) at the next monotonic
     *  generation, returning it. The caller has resolved the TTL ({@code expiresAt}) and the
     *  {@code log_access} opt-in. */
    public Mono<WorkloadConsoleGrant> insertActive(WorkloadConsoleGrant g, long generation) {
        Instant grantedAt = Instant.now();
        // INSERT omits id (filled from the (gen_random_uuid())::text column DEFAULT, changelog
        // 200) and the not-yet-set revoked_at/revoked_by (default NULL); RETURNING id hands back
        // the generated string, mapped into the persisted grant with the SAME field order/values.
        return repo.insertReturningId(g.grantee(), g.targetDomain(),
                        WorkloadConsoleGrant.ACCESS_READ_ONLY, g.logAccess(),
                        WorkloadConsoleGrant.STATE_ACTIVE, g.grantedBy(), grantedAt, g.expiresAt(),
                        g.domain(), WorkloadConsoleGrant.PROP_PENDING, generation)
                .map(genId -> new WorkloadConsoleGrant(genId, g.grantee(), g.targetDomain(),
                        WorkloadConsoleGrant.ACCESS_READ_ONLY, g.logAccess(),
                        WorkloadConsoleGrant.STATE_ACTIVE, g.grantedBy(), grantedAt,
                        g.expiresAt(), null, null, g.domain(),
                        WorkloadConsoleGrant.PROP_PENDING, generation));
    }

    // ── read (admin surface, scoped) ────────────────────────────────────────────

    /** ALL grants VISIBLE to the given tenant scope — the read surface. Scoped admin sees
     *  ONLY their brand's rows; SUPERADMIN sees all. */
    public Flux<WorkloadConsoleGrant> list(PrincipalDomain scope) {
        if (scope == null || scope.scoped()) {
            String domain = scope == null ? PrincipalDomain.NO_DOMAIN : scope.domain();
            return repo.findByDomainOrderByGranteeAscGrantedAtDesc(domain)
                    .map(WorkloadConsoleGrantRow::toDomain);
        }
        return repo.findByOrderByDomainAscGranteeAscGrantedAtDesc()
                .map(WorkloadConsoleGrantRow::toDomain);
    }

    public Mono<WorkloadConsoleGrant> findById(String id) {
        return repo.findById(id).map(WorkloadConsoleGrantRow::toDomain);
    }

    public Mono<Long> maxGeneration() {
        return repo.maxGeneration().defaultIfEmpty(0L);
    }

    // ── revoke (CAS, audited, generation bump) ──────────────────────────────────

    /** CAS {@code active -> revoked} at a NEW generation, guarded on the current state.
     *  Returns rows-updated (1 = won, 0 = already terminal/absent). NEVER deletes. */
    public Mono<Long> revoke(String id, String revokedBy, long newGeneration) {
        return repo.revoke(id, revokedBy, newGeneration);
    }

    // ── expiry sweep (CAS active -> expired for TTL-past grants) ─────────────────

    /** Active grants whose TTL has elapsed — the expiry-sweep working set. UNSCOPED. */
    public Flux<WorkloadConsoleGrant> dueForExpiry(Instant now) {
        return repo.findByStateAndExpiresAtLessThanEqualOrderByExpiresAt(
                        WorkloadConsoleGrant.STATE_ACTIVE, now)
                .map(WorkloadConsoleGrantRow::toDomain);
    }

    /** CAS {@code active -> expired} for one id at a NEW generation. Returns rows-updated
     *  (1 = this sweep won). NEVER deletes. */
    public Mono<Long> markExpired(String id, long newGeneration) {
        return repo.markExpired(id, newGeneration);
    }

    public Mono<Long> updatePropagationState(String id, String propagationState) {
        return repo.updatePropagationState(id, propagationState);
    }
}
