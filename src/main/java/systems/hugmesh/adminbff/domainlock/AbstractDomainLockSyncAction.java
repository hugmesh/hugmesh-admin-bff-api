package systems.hugmesh.adminbff.domainlock;

import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import systems.hugmesh.adminbff.homeserver.HomeserverAdminClient;
import systems.hugmesh.adminbff.homeserver.HomeserverOutcome;
import systems.hugmesh.adminbff.lease.LeaderElection;
import systems.hugmesh.adminbff.provision.ServiceTokenBroker;
import systems.hugmesh.authcore.casdoor.CasdoorAdminClient;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Shared per-platform reconcile shape for the DOMAIN-LOCK loop — the ADD-active
 * sibling of {@link systems.hugmesh.adminbff.suspension.AbstractAccessSyncAction}.
 * Read the desired set, diff it against the world, apply only the diff, idempotent +
 * self-healing, never hard-fail. Concrete subclasses bind the platform domainlocked
 * role + breaker + homeserver force-local verb (akkoma for
 * {@code ROLE_MASTODON_DOMAINLOCKED}, tuwunel for {@code ROLE_MATRIX_DOMAINLOCKED}) and
 * the {@code @Scheduled} tick.
 *
 * <p>The DESIRED state is the {@code domain_lock} active set; this loop is the SOLE
 * caller of {@link CasdoorAdminClient}{@code .add/removeUserFromRole} for the two
 * {@code *_DOMAINLOCKED} MARKER roles (it never touches ROLE_MATRIX/ROLE_MASTODON — the
 * gateway is untouched and the user KEEPS those). Per role the action:
 * <ol>
 *   <li>for every ACTIVE domain_lock row: ENGAGES the homeserver force-local leg
 *       (akkoma per-actor force-local / tuwunel federation-lock; the AUTHORITATIVE
 *       enforcer is the generator MRF + egress reading the active set) and ADDS the
 *       {@code *_DOMAINLOCKED} marker in Casdoor (so the JWT carries it congruently —
 *       a clobber that drops the marker self-heals);</li>
 *   <li>for any Casdoor member of the marker role that is NOT in the active set:
 *       RELEASES the homeserver force-local leg and DROPS the marker (reverse on
 *       unlock — past local-only posts correctly stay local).</li>
 * </ol>
 *
 * <p>SINGLE-WRITER: every tick first checks {@link LeaderElection#isLeader()} and skips
 * entirely when not the leader, so only one replica ever writes Casdoor / the
 * homeserver. The {@link CasdoorAdminClient} is {@code @Nullable} (absent unless
 * {@code casdoor.admin.enabled}) — when null the Casdoor leg is skipped and only the
 * homeserver stub-seam runs, so a Casdoor-less dev run still exercises the loop.
 */
abstract class AbstractDomainLockSyncAction {

    protected final Logger log = LoggerFactory.getLogger(getClass());

    @Nullable
    protected final CasdoorAdminClient casdoor;
    protected final HomeserverAdminClient homeserver;
    protected final DomainLockRepository repo;
    protected final LeaderElection leader;

    protected AbstractDomainLockSyncAction(@Nullable CasdoorAdminClient casdoor,
                                           HomeserverAdminClient homeserver,
                                           DomainLockRepository repo,
                                           LeaderElection leader) {
        this.casdoor = casdoor;
        this.homeserver = homeserver;
        this.repo = repo;
        this.leader = leader;
    }

    /** The platform domainlocked marker role this action reconciles. */
    protected abstract String role();

    /** Engage the homeserver force-local leg for a localpart (akkoma / tuwunel). */
    protected abstract Mono<HomeserverOutcome> engageForceLocal(String localpart);

    /** Release the homeserver force-local leg for a localpart (reverse on unlock). */
    protected abstract Mono<HomeserverOutcome> releaseForceLocal(String localpart);

    /**
     * One reconcile pass for this platform role. Leader-gated; idempotent. Returns
     * normally even on partial failure (the loop is the backstop). Concrete classes
     * wrap this in {@code @CircuitBreaker(name=...)} so a stalled homeserver/Casdoor
     * opens the breaker and the next tick retries.
     */
    protected Mono<Void> reconcile() {
        if (!leader.isLeader()) {
            log.debug("[domain-lock {}] not leader ({}) — skipping tick", role(), leader.label());
            return Mono.empty();
        }
        Mono<List<DomainLock>> active = repo.activeByRole(role()).collectList();
        Mono<List<String>> members = casdoorMembers();
        return Mono.zip(active, members)
                .flatMap(t -> applyDiff(t.getT1(), t.getT2()))
                .onErrorResume(e -> {
                    log.warn("[domain-lock {}] tick failed (will retry next tick): {}", role(), e.toString());
                    return Mono.empty();
                });
    }

    /**
     * Apply the desired state: ENGAGE force-local + ADD the marker for every active
     * lock, and RELEASE + DROP the marker for any Casdoor marker-member NOT in the
     * active set (a stray / unlocked user).
     */
    private Mono<Void> applyDiff(List<DomainLock> active, List<String> members) {
        Set<String> lockedLocalparts = new HashSet<>();
        Set<String> lockedUsers = new HashSet<>();
        for (DomainLock l : active) {
            lockedLocalparts.add(l.localpart());
            lockedUsers.add(userIdFor(l.casdoorUser()));
        }

        // 1) ENGAGE every active lock: homeserver force-local FIRST, Casdoor marker ADD.
        Mono<Void> enforce = Flux.fromIterable(active)
                .concatMap(this::enforceLock)
                .then();

        // 2) RELEASE any current Casdoor marker-member NOT under an active lock (heals
        //    a stray force-local / completes an unlock). The desired marker set is
        //    EXACTLY the active locks; anyone else carrying the marker is reversed.
        Mono<Void> release = Flux.fromIterable(members)
                .map(this::userIdFor)
                .filter(id -> !lockedUsers.contains(id))
                .distinct()
                .concatMap(id -> releaseForceLocal(localpartOf(id)).then(dropRole(id)))
                .then();

        return enforce.then(release);
    }

    /**
     * ENGAGE ordering for one active lock: (1) engage the homeserver force-local leg
     * (the authoritative-congruence leg); (2) ADD the {@code *_DOMAINLOCKED} marker in
     * Casdoor (so the JWT carries it). The marker ADD is applied EVERY tick an active
     * lock exists — that is what self-heals a concurrent marker-drop clobber. The
     * homeserver leg's outcome sets propagation_state (a stubbed/degraded leg keeps the
     * row {@code pending}/{@code degraded} so a later tick — once the MRF/egress are
     * real — re-applies it).
     */
    private Mono<Void> enforceLock(DomainLock l) {
        return engageForceLocal(l.localpart())
                .flatMap(outcome ->
                        addRole(l.casdoorUser())                          // marker: always add
                                .then(repo.updatePropagationState(l.id(), propagationFor(outcome)))
                                .then());
    }

    private static String propagationFor(HomeserverOutcome outcome) {
        if (outcome.isOk()) return DomainLock.PROP_APPLIED;
        if (outcome.isStubbed()) return DomainLock.PROP_PENDING;
        return DomainLock.PROP_DEGRADED;
    }

    // ── Casdoor single-writer legs (the ONLY caller of add/removeUserFromRole for
    //    the *_DOMAINLOCKED MARKER roles — never touches ROLE_MATRIX/ROLE_MASTODON) ──
    protected Mono<List<String>> casdoorMembers() {
        return (casdoor == null) ? Mono.just(List.of()) : casdoor.getRoleMembers(role());
    }

    protected Mono<Void> addRole(String casdoorUser) {
        if (casdoor == null) return Mono.empty();
        return casdoor.addUserToRole(role(), userIdFor(casdoorUser))
                .onErrorResume(e -> {
                    log.warn("[domain-lock {}] addUserToRole {} failed (retry next tick): {}",
                            role(), casdoorUser, e.toString());
                    return Mono.empty();
                });
    }

    protected Mono<Void> dropRole(String userId) {
        if (casdoor == null) return Mono.empty();
        return casdoor.removeUserFromRole(role(), userId)
                .onErrorResume(e -> {
                    log.warn("[domain-lock {}] removeUserFromRole {} failed (retry next tick): {}",
                            role(), userId, e.toString());
                    return Mono.empty();
                });
    }

    /**
     * The Casdoor member id ({@code org/username}) for a grantee. If already in
     * {@code org/username} form it is passed through; a bare username is prefixed with
     * the client's organization.
     */
    protected String userIdFor(String casdoorUser) {
        if (casdoorUser == null) return null;
        if (casdoorUser.contains("/")) return casdoorUser;
        String org = casdoor == null ? "hugmesh" : casdoor.organization();
        return org + "/" + casdoorUser;
    }

    /** The homeserver localpart for a Casdoor member id (strip org/ + provider:). */
    protected static String localpartOf(String userId) {
        return ServiceTokenBroker.matrixUser(DomainLockService.localpartSeed(userId));
    }
}
