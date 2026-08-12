package net.hugmesh.adminbff.appeal;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import net.hugmesh.adminbff.suspension.AccessSuspension;
import net.hugmesh.adminbff.suspension.SuspensionService;
import net.hugmesh.commons.security.PrincipalDomain;

/**
 * Write/read surface for {@code account_appeal} — a curtailed principal's OWN
 * structured appeal against their {@code access_suspension} {@code PROFILE} state,
 * and the admin decision over it.
 *
 * <h3>owner == subject (fail-closed)</h3>
 * Submit stamps {@code userSub}/{@code handle} = the JWT-resolved account's own
 * identity and {@code domain} = the validated issuer (all controller-derived, never
 * body fields). The user read is double-scoped (userSub + domain) so a user only ever
 * sees their OWN appeals.
 *
 * <h3>an APPROVE decide actually restores access — never a bare status flip</h3>
 * {@link #decide} is the honesty keystone this feature exists for: on
 * {@link AccountAppeal#STATUS_APPROVED} it calls
 * {@link SuspensionService#clearByHandle} for the appellant's {@code PROFILE} row
 * FIRST, and the appeal row's CAS {@code PENDING -> APPROVED} write only runs
 * {@code .then()} that call succeeds. If the underlying clear errors, the {@code Mono}
 * errors and the appeal row is NEVER updated — it stays {@code PENDING}, so a failed
 * restore can never render as an applied approval (the platform's honest-envelope
 * invariant). A DENY needs no restore leg and CASes directly.
 *
 * <p>{@code clearByHandle} (NOT the exact-string {@code SuspensionService#clear}) is
 * deliberate: the appellant's own bare handle can differ in STRING FORM from whatever
 * a banning admin free-typed as the ban target (a {@code provider:handle} id, an
 * {@code org/username} member string, …) while still being the SAME homeserver
 * localpart. {@code clearByHandle} matches on that normalized localpart — the same
 * one {@code statusFor} reads to gate {@code /bff/me}/{@code /bff/login} — so a
 * "cleared 0 rows" result is never a silent matching miss; it is mathematically the
 * same read the access gate itself performs, i.e. a genuinely already-unrestricted
 * state. See {@link SuspensionService#clearByHandle} for the full rationale.
 */
@Service
public class AccountAppealService {

    private static final Logger log = LoggerFactory.getLogger(AccountAppealService.class);

    private final AccountAppealRepository repo;
    private final SuspensionService suspensions;

    public AccountAppealService(AccountAppealRepository repo, SuspensionService suspensions) {
        this.repo = repo;
        this.suspensions = suspensions;
    }

    /**
     * Submit a new PENDING appeal, or return the appellant's EXISTING pending appeal
     * unchanged (idempotent — mirrors {@code SuspensionService.suspend}'s
     * existing-active no-op pattern; a curtailed user re-visiting the appeal page must
     * not spam duplicate rows). {@code userSub}/{@code handle}/{@code domain} are
     * caller-derived.
     */
    public Mono<AccountAppeal> submit(String userSub, String handle, String domain,
                                      String reason, String contactEmail) {
        return repo.findPendingForUser(userSub, domain)
                .doOnNext(existing -> log.info("[account-appeal] {} already has a pending appeal (id={}) — no-op submit",
                        userSub, existing.id()))
                .switchIfEmpty(Mono.defer(() -> repo.insertPending(userSub, handle, domain, reason, contactEmail)
                        .doOnNext(a -> log.info("[account-appeal] submit userSub={} handle={} domain={} id={}",
                                userSub, handle, domain, a.id()))));
    }

    /** The appellant's OWN appeals (owner == subject). */
    public Flux<AccountAppeal> listMine(String userSub, String domain) {
        return repo.listForUser(userSub, domain);
    }

    /** ALL appeals VISIBLE to the acting admin (own brand; SUPERADMIN all) — the inbox. */
    public Flux<AccountAppeal> listForAdmin(PrincipalDomain scope) {
        return repo.list(scope);
    }

    /**
     * Decide an appeal (CAS {@code PENDING -> newStatus}, brand-scoped, single-winner).
     * On {@code APPROVED} the underlying {@code PROFILE} suspension is cleared FIRST —
     * an error there propagates and the appeal row is left {@code PENDING} (never a
     * dishonest "approved but nothing restored"). Returns rows-updated (1 = decided,
     * 0 = already decided / absent / out of scope).
     */
    public Mono<Long> decide(String id, String newStatus, String decidedBy, PrincipalDomain scope) {
        return repo.findById(id, scope)
                .filter(a -> AccountAppeal.STATUS_PENDING.equals(a.status()))
                // Mono.defer: the CAS write must be a LAZY reference, never evaluated
                // until the restore leg above has already completed successfully — an
                // eager repo.decide(...) call here would run (and could be observed as
                // "decided") even when restoreIfApproved goes on to error.
                .flatMap(appeal -> restoreIfApproved(appeal, newStatus, decidedBy, scope)
                        .then(Mono.defer(() -> repo.decide(id, newStatus, decidedBy, scope)))
                        .doOnNext(n -> log.info("[account-appeal] decide id={} -> {} by={} rows={}",
                                id, newStatus, decidedBy, n)))
                .defaultIfEmpty(0L);
    }

    /**
     * APPROVE only: clear the appellant's PROFILE suspension by LOCALPART (never an
     * exact-string match — see the class javadoc). DENY: no-op.
     */
    private Mono<Void> restoreIfApproved(AccountAppeal appeal, String newStatus, String decidedBy,
                                         PrincipalDomain scope) {
        if (!AccountAppeal.STATUS_APPROVED.equals(newStatus)) {
            return Mono.empty();
        }
        return suspensions.clearByHandle(AccessSuspension.ROLE_PROFILE, appeal.handle(), decidedBy, scope)
                .doOnNext(cleared -> {
                    if (cleared > 0) {
                        log.info("[account-appeal] approve id={} restored PROFILE access for handle={} (rows={})",
                                appeal.id(), appeal.handle(), cleared);
                    } else {
                        log.info("[account-appeal] approve id={} handle={} had no active PROFILE row to clear "
                                        + "(already unrestricted by the same localpart the access gate reads)",
                                appeal.id(), appeal.handle());
                    }
                })
                .then();
    }
}
