package net.hugmesh.adminbff.suspension;
import net.hugmesh.authcore.account.AccountStatus;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.reactive.TransactionalOperator;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import net.hugmesh.adminbff.notification.AccountRestrictionPayload;
import net.hugmesh.adminbff.notification.NotificationOutbox;
import net.hugmesh.adminbff.notification.NotifyChannelDirective;
import net.hugmesh.adminbff.notification.NotificationOutboxRepository;
import net.hugmesh.adminbff.provision.ServiceTokenBroker;
import net.hugmesh.commons.security.PrincipalDomain;

import java.time.Duration;
import java.time.Instant;
import java.util.List;

/**
 * The desired-state API the endpoints call: write / clear an {@code access_suspension}
 * row and trigger a reconcile tick. It is DELIBERATELY the only write surface for
 * suspensions — it NEVER touches Casdoor or the homeserver directly. The
 * single-writer reconcile loop ({@link AccessSyncActions}) is the sole effector, so
 * an endpoint write + tick converges the world to the table.
 *
 * <p>This split is the core invariant: endpoints mutate the table and ask for a
 * tick; the loop (behind a k8s Lease, single writer) reads the table and drives
 * Casdoor + the homeserver. A Casdoor clobber therefore self-heals on the next tick.
 */
@Service
public class SuspensionService {

    private static final Logger log = LoggerFactory.getLogger(SuspensionService.class);

    private final AccessSuspensionRepository repo;
    private final AccessSyncActions actions;
    /** The transactional-outbox sink: a notification_outbox row is written in the SAME
     *  reactive transaction as the access_suspension effect write (see {@link #suspend}).
     *  SHIPS DARK — nothing consumes the outbox yet (the hugmesh-actions reconciler
     *  is PR4). */
    private final NotificationOutboxRepository outbox;
    /** Wraps the effect write + the outbox write in ONE reactive transaction so the
     *  outbox row exists IFF the effect commits (lossless transactional outbox); a
     *  failure of either leg rolls BOTH back. */
    private final TransactionalOperator tx;

    public SuspensionService(AccessSuspensionRepository repo, AccessSyncActions actions,
                             NotificationOutboxRepository outbox, TransactionalOperator tx) {
        this.repo = repo;
        this.actions = actions;
        this.outbox = outbox;
        this.tx = tx;
    }

    /**
     * Suspend {@code casdoorUser} from {@code role}. Writes an ACTIVE
     * access_suspension row (idempotent — an existing active row is returned
     * unchanged) and triggers a reconcile tick. {@code ttlSeconds} null = permanent
     * (expires_at NULL, restore_role=false); a positive ttl sets expires_at and
     * restore_role=true so the expiry action auto-restores at TTL.
     *
     * @return the active suspension row (existing or newly created)
     */
    public Mono<AccessSuspension> suspend(String role, String casdoorUser, Long ttlSeconds,
                                          String reason, String setBy, PrincipalDomain scope) {
        return suspend(role, casdoorUser, ttlSeconds, reason, setBy, scope, null);
    }

    /**
     * As {@link #suspend(String, String, Long, String, String, PrincipalDomain)}, carrying
     * the moderator's {@code notifyChannels} directive into the outbox row's payload (see
     * {@link NotifyChannelDirective}). An absent or empty list is today's behaviour.
     * If an active suspension already exists this is the idempotent no-op and the new
     * request's directive is dropped (first request wins, as for the reason).
     */
    public Mono<AccessSuspension> suspend(String role, String casdoorUser, Long ttlSeconds,
                                          String reason, String setBy, PrincipalDomain scope,
                                          List<String> notifyChannels) {
        String localpart = ServiceTokenBroker.matrixUser(localpartSeed(casdoorUser));
        boolean permanent = ttlSeconds == null;
        Instant expiresAt = permanent ? null : Instant.now().plus(Duration.ofSeconds(ttlSeconds));
        boolean restoreRole = !permanent;
        String domain = scope == null ? PrincipalDomain.NO_DOMAIN : scope.domain();
        // DOMAIN scoping: an existing active row is only the idempotent no-op when it
        // is visible to THIS scope (a scoped admin never observes another brand's row);
        // the new row is stamped with the acting principal's own domain.
        return repo.findActive(casdoorUser, role, scope)
                .doOnNext(existing -> log.info("[suspension] {} already active for {} (id={}) — no-op write",
                        role, casdoorUser, existing.id()))
                // NEW active row: write the effect AND the transactional-outbox row in
                // ONE reactive transaction. The no-op branch above produces NO outbox row
                // (an idempotent re-ban is not a new restriction event), so the outbox
                // INSERT lives ONLY in this switchIfEmpty defer.
                .switchIfEmpty(Mono.defer(() -> insertSuspensionWithOutbox(
                        casdoorUser, localpart, role, expiresAt, restoreRole, reason, setBy,
                        ttlSeconds, domain, notifyChannels)))
                // Trigger a reconcile tick (best-effort; the @Scheduled loop is the
                // backstop so a failed manual tick still converges on the next sweep).
                // This is OUTSIDE the transaction: the tick does external Casdoor /
                // homeserver calls and must never be enrolled in (or roll back) the DB tx.
                .flatMap(s -> actions.triggerTick().thenReturn(s));
    }

    /**
     * Atomically write the access_suspension effect row AND its notification_outbox row
     * in the SAME reactive transaction (lossless transactional-outbox pattern): the
     * outbox row exists IFF the effect commits, and a failure of EITHER leg rolls BOTH
     * back. The outbox payload carries reason/ttl/target ONLY — NEVER {@code setBy}
     * (the acting mod/admin identity): the {@code @system} sender is neutral.
     *
     * <p>SHIPS DARK: the outbox row is written but NOTHING consumes it yet (the
     * hugmesh-actions reconciler is PR4) — the only observable change of this whole
     * PR is this extra row per new ban/timeout.
     */
    private Mono<AccessSuspension> insertSuspensionWithOutbox(
            String casdoorUser, String localpart, String role, Instant expiresAt,
            boolean restoreRole, String reason, String setBy, Long ttlSeconds, String domain,
            List<String> notifyChannels) {
        return repo.insertActive(casdoorUser, localpart, role, expiresAt, restoreRole, reason, setBy, domain)
                .doOnNext(s -> log.info("[suspension] created {} for {} (id={}, ttl={}s, domain={})",
                        role, casdoorUser, s.id(), ttlSeconds, s.domain()))
                .flatMap(s -> outbox.insert(
                                s.domain(),
                                NotificationOutbox.SOURCE_ACCESS_SUSPENSION,
                                s.id(),
                                NotificationOutbox.CATEGORY_ACCOUNT_RESTRICTION,
                                // NOTE: no setBy / actor — neutral @system payload.
                                AccountRestrictionPayload.build(casdoorUser, role, ttlSeconds, reason, notifyChannels))
                        .thenReturn(s))
                // ── The transaction boundary: both INSERTs commit together or not at
                // all. as(tx::transactional) enrolls the whole effect+outbox pipeline. ──
                .as(tx::transactional);
    }

    /**
     * Clear the active suspension for {@code casdoorUser}/{@code role} (CAS
     * active->restored) and trigger a reconcile tick so the role + homeserver state
     * are restored. A no-op (empty) if there is no active suspension.
     *
     * <p>NOTE: {@code casdoorUser} is matched by an EXACT STRING
     * ({@link AccessSuspensionRepository#findActive}). This is ONLY safe for a caller
     * that is guaranteed to already hold the identical string form the row was
     * originally banned with (e.g. re-using a value read straight off
     * {@link #listActive}). Any caller that resolves its target from free-text input —
     * including an admin typing a handle, since a different string form than the
     * original ({@code google:alice@x.com} vs the bare handle {@code alice@x.com})
     * would silently no-op here — must use {@link #clearByHandle} instead, which
     * matches on the normalized localpart rather than requiring an exact string match.
     * Both {@code AdminController.clearAccessRole} (direct admin lift) and the
     * account-appeal APPROVE flow use {@link #clearByHandle} for exactly this reason.
     */
    public Mono<Void> clear(String role, String casdoorUser, String clearedBy, PrincipalDomain scope) {
        // DOMAIN scoping: a scoped admin can only resolve (and therefore clear) a row
        // in their own brand; another brand's active suspension is invisible, so the
        // findActive is empty and the clear is a no-op for them. SUPERADMIN clears any.
        return repo.findActive(casdoorUser, role, scope)
                .flatMap(active -> repo.markRestored(active.id())
                        .doOnNext(n -> log.info("[suspension] cleared {} for {} by {} (id={}, rows={})",
                                role, casdoorUser, clearedBy, active.id(), n)))
                .then(actions.triggerTick());
    }

    /**
     * Clear ALL active {@code role} suspensions whose stored {@code localpart}
     * matches the localpart DERIVED from {@code handle} — the same normalization
     * {@link #statusFor} already uses to gate {@code /bff/me} / {@code /bff/login}
     * (see {@link #localpartSeed} + {@link ServiceTokenBroker#matrixUser}) — rather
     * than an exact {@code casdoor_user} string match.
     *
     * <p>This exists because a banning admin's free-text target (a bare handle, a
     * {@code provider:handle} id, or a Casdoor {@code org/username} member string)
     * can differ in STRING FORM from the appellant's own bare handle while still
     * resolving to the identical homeserver localpart. An exact-string {@link #clear}
     * would silently miss such a row — a "cosmetic" restore where the appeal flips to
     * APPROVED but the underlying ban is untouched. This method cannot have that
     * failure mode: it reads the SAME localpart the access gate itself reads, so
     * "found nothing" here is mathematically equivalent to "{@link #statusFor} does
     * not consider this localpart {@code role}-restricted" — a genuinely resolved
     * state, not a matching miss.
     *
     * @return the number of rows ACTUALLY cleared (0 is not an error — by the
     * equivalence above it honestly means there was nothing to restore)
     */
    public Mono<Long> clearByHandle(String role, String handle, String clearedBy, PrincipalDomain scope) {
        String localpart = ServiceTokenBroker.matrixUser(localpartSeed(handle));
        if (localpart == null || localpart.isBlank()) {
            return Mono.just(0L);
        }
        boolean scopedRead = scope != null && scope.scoped();
        String domain = scopedRead ? scope.domain() : null;
        return repo.activeByLocalpartAndRole(localpart, role)
                .filter(s -> domain == null || domain.equals(s.domain()))
                .flatMap(s -> repo.markRestored(s.id())
                        .doOnNext(n -> log.info(
                                "[suspension] cleared {} for localpart={} (casdoorUser={}) by {} (id={}, rows={})",
                                role, localpart, s.casdoorUser(), clearedBy, s.id(), n)))
                .reduce(0L, Long::sum)
                .flatMap(cleared -> actions.triggerTick().thenReturn(cleared));
    }

    /** All active suspensions VISIBLE to the given tenant scope (admin read surface).
     *  Scoped admin sees only their brand; SUPERADMIN sees all. */
    public Flux<AccessSuspension> listActive(PrincipalDomain scope) {
        return repo.allActive(scope);
    }

    /** Is this localpart currently suspended on a platform role (the broker guard)? */
    public Mono<Boolean> isLocalpartSuspended(String localpart, String role) {
        return repo.activeByLocalpartAndRole(localpart, role).hasElements();
    }

    /**
     * The BFF-computed account-STATE for a principal handle — {@code active} /
     * {@code suspended} / {@code banned} — read off the {@code access_suspension}
     * desired-state for the caller's derived localpart. The {@code /bff/me} +
     * {@code /bff/login} surface so the host appeal-gate + login-ui know whether the
     * caller is usable. This reads the principal's OWN rows only and is DELIBERATELY
     * unscoped: a suspension is keyed to the person, not the reader's tenant, so the
     * answer is identical regardless of who asks. A null/blank handle (no principal)
     * resolves to {@link AccountStatus#active()} (fail-OPEN here is correct — absence
     * of a suspension row is "usable"; this is a read, not an authz gate, and the
     * platform-role gates + the broker guard remain fail-CLOSED).
     *
     * <p>Reduction (dominant row wins): a {@code PROFILE} permanent ban
     * ({@code expires_at} NULL) → {@code banned}; a timed {@code PROFILE} OR any
     * platform-role suspension → {@code suspended} (carrying the earliest expiry);
     * no active rows → {@code active}.
     */
    public Mono<AccountStatus> statusFor(String handle) {
        String localpart = ServiceTokenBroker.matrixUser(localpartSeed(handle));
        if (localpart == null || localpart.isBlank()) {
            return Mono.just(AccountStatus.active());
        }
        return repo.activeByLocalpart(localpart).collectList().map(SuspensionService::reduce);
    }

    /** Reduce a principal's active suspension rows to one {@link AccountStatus}. */
    static AccountStatus reduce(java.util.List<AccessSuspension> rows) {
        if (rows == null || rows.isEmpty()) return AccountStatus.active();
        // A permanent PROFILE suspension is a full ban (no auto-restore).
        for (AccessSuspension s : rows) {
            if (AccessSuspension.ROLE_PROFILE.equals(s.role()) && s.expiresAt() == null) {
                return new AccountStatus(AccountStatus.BANNED, null, s.reason());
            }
        }
        // Otherwise SUSPENDED — surface the earliest expiry + a reason (if any).
        Instant earliest = null;
        String reason = null;
        for (AccessSuspension s : rows) {
            if (s.expiresAt() != null && (earliest == null || s.expiresAt().isBefore(earliest))) {
                earliest = s.expiresAt();
            }
            if (reason == null && s.reason() != null && !s.reason().isBlank()) {
                reason = s.reason();
            }
        }
        return new AccountStatus(AccountStatus.SUSPENDED, earliest, reason);
    }

    /**
     * The seed for the homeserver localpart of a grantee identifier. Grantees may be
     * a bare username, a {@code provider:handle} id, or a Casdoor {@code org/username}
     * member — strip any leading {@code provider:} / {@code org/} prefix so the
     * localpart is derived from the handle.
     */
    static String localpartSeed(String casdoorUser) {
        if (casdoorUser == null) return "";
        String s = casdoorUser;
        int slash = s.lastIndexOf('/');
        if (slash >= 0) s = s.substring(slash + 1);
        int colon = s.indexOf(':');
        if (colon >= 0) s = s.substring(colon + 1);
        return s;
    }
}
