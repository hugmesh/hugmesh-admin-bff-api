package net.hugmesh.adminbff.domainlock;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import net.hugmesh.adminbff.homeserver.HomeserverAdminClient;
import net.hugmesh.adminbff.provision.ServiceTokenBroker;
import net.hugmesh.commons.security.PrincipalDomain;

/**
 * The desired-state API the endpoints call: write / clear a {@code domain_lock} row and
 * trigger a reconcile tick. It is DELIBERATELY the only write surface for domain locks
 * — it never drives Casdoor or the homeserver from the endpoint thread EXCEPT the
 * synchronous lock-immediacy enforce on {@link #lock} (below). The single-writer
 * reconcile loop ({@link DomainLockSyncActions} / the platform actions) is the steady
 * effector, so an endpoint write + tick converges the world to the table.
 *
 * <p>This is the ADD-active sibling of
 * {@link net.hugmesh.adminbff.suspension.SuspensionService}: an active row means
 * "force this user local-only" (ADD/KEEP the {@code *_DOMAINLOCKED} marker), not "drop
 * the role". The set of ACTIVE rows IS the force-local allowlist the generator akkoma
 * MRF / egress proxy reads, so writing the row already materializes the actor into the
 * force-local set.
 *
 * <h3>LOCK-IMMEDIACY (close the post-and-federate window)</h3>
 * <p>The steady reconcile loop runs on a ~30s tick; a freshly-locked user could
 * post-and-federate in that window. So {@link #lock} does a SYNCHRONOUS out-of-band
 * enforce right after writing the desired-state row: it engages the homeserver
 * force-local leg ({@link HomeserverAdminClient#forceLocalMastodon} /
 * {@link HomeserverAdminClient#federationLockMatrix}) immediately so the actor is in the
 * force-local set with no tick delay. That leg is the GATED STUB-SEAM
 * ({@code homeserver.domainlock.enabled} default off, never hard-fail), so today it is a
 * no-op STUBBED outcome — but the seam fires synchronously the instant it is wired on.
 * The reconcile loop remains the backstop (it re-applies + reconciles propagation_state
 * + the Casdoor marker), so a failed synchronous enforce still converges.
 */
@Service
public class DomainLockService {

    private static final Logger log = LoggerFactory.getLogger(DomainLockService.class);

    private final DomainLockRepository repo;
    private final DomainLockSyncActions actions;
    private final HomeserverAdminClient homeserver;

    public DomainLockService(DomainLockRepository repo, DomainLockSyncActions actions,
                             HomeserverAdminClient homeserver) {
        this.repo = repo;
        this.actions = actions;
        this.homeserver = homeserver;
    }

    /**
     * Domain-lock {@code casdoorUser} on {@code role} (one of the two
     * {@code *_DOMAINLOCKED} markers). Writes an ACTIVE domain_lock row (idempotent — an
     * existing active row is returned unchanged), does the SYNCHRONOUS lock-immediacy
     * enforce, then triggers a reconcile tick.
     *
     * @return the active domain_lock row (existing or newly created)
     */
    public Mono<DomainLock> lock(String role, String casdoorUser, String reason, String setBy,
                                 PrincipalDomain scope) {
        String localpart = ServiceTokenBroker.matrixUser(localpartSeed(casdoorUser));
        // DOMAIN scoping: a scoped admin only observes (and no-ops on) an existing lock
        // in THEIR brand; the new row is stamped with the acting principal's domain.
        return repo.findActive(casdoorUser, role, scope)
                .doOnNext(existing -> log.info("[domain-lock] {} already active for {} (id={}) — no-op write",
                        role, casdoorUser, existing.id()))
                .switchIfEmpty(Mono.defer(() ->
                        repo.insertActive(casdoorUser, localpart, role, reason, setBy,
                                        scope == null ? PrincipalDomain.NO_DOMAIN : scope.domain())
                                .doOnNext(l -> log.info("[domain-lock] created {} for {} (id={}, domain={})",
                                        role, casdoorUser, l.id(), l.domain()))))
                // LOCK-IMMEDIACY: engage the force-local leg synchronously so there is
                // no post-and-federate window before the next tick (best-effort; the
                // @Scheduled loop is the backstop). Then trigger a reconcile tick.
                .flatMap(l -> enforceNow(role, localpart)
                        .then(actions.triggerTick())
                        .thenReturn(l));
    }

    /**
     * Lift the active domain-lock for {@code casdoorUser}/{@code role} (CAS
     * active->removed) and trigger a reconcile tick so the force-local leg + the Casdoor
     * marker are reversed (past local-only posts correctly stay local). A no-op (empty)
     * if there is no active lock.
     */
    public Mono<Void> unlock(String role, String casdoorUser, String clearedBy, PrincipalDomain scope) {
        String localpart = ServiceTokenBroker.matrixUser(localpartSeed(casdoorUser));
        // DOMAIN scoping: a scoped admin can only resolve (and unlock) a lock in their
        // own brand; another brand's lock is invisible (no-op). SUPERADMIN unlocks any.
        return repo.findActive(casdoorUser, role, scope)
                .flatMap(active -> repo.markRemoved(active.id())
                        .doOnNext(n -> log.info("[domain-lock] unlocked {} for {} by {} (id={}, rows={})",
                                role, casdoorUser, clearedBy, active.id(), n)))
                // Release the force-local leg synchronously (best-effort; the loop also
                // releases + drops the marker for any non-active member on its tick).
                .then(releaseNow(role, localpart))
                .then(actions.triggerTick());
    }

    /** All active domain locks VISIBLE to the given tenant scope (admin read surface).
     *  Scoped admin sees only their brand; SUPERADMIN sees all. The force-local
     *  allowlist materialization uses the UNSCOPED {@link #listActiveByRole(String)}
     *  (enforcement is platform-wide). */
    public Flux<DomainLock> listActive(PrincipalDomain scope) {
        return repo.allActive(scope);
    }

    /** Active locks for a single platform marker role (the per-platform force-local set). */
    public Flux<DomainLock> listActiveByRole(String role) {
        return repo.activeByRole(role);
    }

    /** Is this localpart currently domain-locked on a platform marker role? */
    public Mono<Boolean> isLocalpartLocked(String localpart, String role) {
        return repo.activeByLocalpartAndRole(localpart, role).hasElements();
    }

    // ── Synchronous lock-immediacy legs (GATED stub-seam; never hard-fail) ──────
    private Mono<Void> enforceNow(String role, String localpart) {
        return forceLocal(role, localpart, true)
                .onErrorResume(e -> {
                    log.warn("[domain-lock] synchronous enforce {} for {} failed (loop will heal): {}",
                            role, localpart, e.toString());
                    return Mono.empty();
                }).then();
    }

    private Mono<Void> releaseNow(String role, String localpart) {
        return forceLocal(role, localpart, false)
                .onErrorResume(e -> {
                    log.warn("[domain-lock] synchronous release {} for {} failed (loop will heal): {}",
                            role, localpart, e.toString());
                    return Mono.empty();
                }).then();
    }

    private Mono<?> forceLocal(String role, String localpart, boolean on) {
        return switch (role) {
            case DomainLock.ROLE_MASTODON_DOMAINLOCKED -> homeserver.forceLocalMastodon(localpart, on);
            case DomainLock.ROLE_MATRIX_DOMAINLOCKED -> homeserver.federationLockMatrix(localpart, on);
            default -> Mono.empty();
        };
    }

    /**
     * The seed for the homeserver localpart of a grantee identifier. Grantees may be a
     * bare username, a {@code provider:handle} id, or a Casdoor {@code org/username}
     * member — strip any leading {@code provider:} / {@code org/} prefix so the
     * localpart is derived from the handle. (Mirrors
     * {@code SuspensionService.localpartSeed}.)
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
