package systems.hugmesh.adminbff.appeal;

import org.springframework.stereotype.Repository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import systems.hugmesh.commons.security.PrincipalDomain;

import java.time.Instant;

/**
 * Reactive (R2DBC) store for {@code account_appeal} — the ACCOUNT-ban appeal record
 * (schema in Liquibase {@code db/changelog/250-account-appeals.xml}).
 *
 * <p>Backed by the Spring Data {@link AccountAppealR2dbcRepository} (no raw
 * {@code DatabaseClient}); maps the {@link AccountAppealRow} entity to/from the
 * {@link AccountAppeal} domain record.
 *
 * <h3>owner == subject (the user read is double-scoped)</h3>
 * {@link #listForUser} filters on BOTH {@code domain} AND {@code userSub} so a user
 * can ONLY ever see their OWN appeals. The ADMIN read ({@link #list}) is brand-scoped
 * via the usual {@code scope.scoped() ? WHERE domain : unscoped} branch. The decide is
 * a SCOPED CAS {@code PENDING -> APPROVED/DENIED} (never deleted = audit).
 */
@Repository
public class AccountAppealRepository {

    private final AccountAppealR2dbcRepository repo;

    public AccountAppealRepository(AccountAppealR2dbcRepository repo) {
        this.repo = repo;
    }

    // ── submit (user; owner == subject) ─────────────────────────────────────────

    /** Insert a new PENDING appeal (app-generated id). {@code userSub}/{@code handle}/
     *  {@code domain} are caller-derived, never body fields. */
    public Mono<AccountAppeal> insertPending(String userSub, String handle, String domain,
                                             String reason, String contactEmail) {
        Instant submittedAt = Instant.now();
        return repo.insertReturningId(userSub, handle, domain, reason, contactEmail,
                        AccountAppeal.STATUS_PENDING, submittedAt)
                .map(genId -> new AccountAppeal(genId, userSub, handle, domain, reason,
                        contactEmail, AccountAppeal.STATUS_PENDING, submittedAt, null, null));
    }

    // ── user read (owner == subject; double-scoped) ─────────────────────────────

    /** The appellant's OWN appeals in their OWN brand (negative cross-user isolation). */
    public Flux<AccountAppeal> listForUser(String userSub, String domain) {
        return repo.findByUserSubAndDomainOrderBySubmittedAtDesc(userSub, domain)
                .map(AccountAppealRow::toDomain);
    }

    /** The appellant's most recent PENDING appeal, if any (idempotent re-submit guard —
     *  mirrors {@code SuspensionService.suspend}'s existing-active no-op pattern). */
    public Mono<AccountAppeal> findPendingForUser(String userSub, String domain) {
        return repo.findFirstByUserSubAndDomainAndStatusOrderBySubmittedAtDesc(
                        userSub, domain, AccountAppeal.STATUS_PENDING)
                .map(AccountAppealRow::toDomain);
    }

    // ── admin read (brand-scoped) ───────────────────────────────────────────────

    /** ALL appeals VISIBLE to the given tenant scope — the ADMIN inbox (own brand;
     *  SUPERADMIN all). */
    public Flux<AccountAppeal> list(PrincipalDomain scope) {
        if (scope == null || scope.scoped()) {
            String domain = scope == null ? PrincipalDomain.NO_DOMAIN : scope.domain();
            return repo.findByDomainOrderBySubmittedAtDesc(domain).map(AccountAppealRow::toDomain);
        }
        return repo.findByOrderByDomainAscSubmittedAtDesc().map(AccountAppealRow::toDomain);
    }

    /** One appeal by id, SCOPED (a scoped admin cannot resolve another brand's appeal). */
    public Mono<AccountAppeal> findById(String id, PrincipalDomain scope) {
        if (scope == null || scope.scoped()) {
            String domain = scope == null ? PrincipalDomain.NO_DOMAIN : scope.domain();
            return repo.findByIdAndDomain(id, domain).map(AccountAppealRow::toDomain);
        }
        return repo.findById(id).map(AccountAppealRow::toDomain);
    }

    // ── decide (admin; scoped CAS PENDING -> terminal) ──────────────────────────

    /**
     * Compare-and-swap {@code PENDING -> newStatus} for one appeal, SCOPED so a scoped
     * admin can only decide their own brand's appeals AND only from {@code PENDING}
     * (single-winner; a second decide is a no-op). Stamps {@code decided_by}/
     * {@code decided_at}. Returns rows-updated (1 = decided, 0 = already decided /
     * absent / out of scope). CALLERS: the CAS write must run AFTER any underlying
     * effect (e.g. {@code SuspensionService.clear} on approve) has ALREADY succeeded —
     * see {@link AccountAppealService#decide} — so a failed effect never lets the row
     * flip to APPROVED.
     */
    public Mono<Long> decide(String id, String newStatus, String decidedBy, PrincipalDomain scope) {
        if (scope == null || scope.scoped()) {
            String domain = scope == null ? PrincipalDomain.NO_DOMAIN : scope.domain();
            return repo.decideScoped(id, newStatus, decidedBy, domain);
        }
        return repo.decideAll(id, newStatus, decidedBy);
    }
}
