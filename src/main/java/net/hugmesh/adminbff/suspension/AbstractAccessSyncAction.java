package net.hugmesh.adminbff.suspension;

import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import net.hugmesh.adminbff.homeserver.HomeserverAdminClient;
import net.hugmesh.adminbff.homeserver.HomeserverOutcome;
import net.hugmesh.adminbff.lease.LeaderElection;
import net.hugmesh.adminbff.provision.ServiceTokenBroker;
import net.hugmesh.authcore.casdoor.CasdoorAdminClient;
import net.hugmesh.authcore.provision.GatewayRevocationClient;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Shared per-platform reconcile shape for the access_suspension loop, modeled on the
 * hugmesh-actions {@code GameMasterAdminSyncAction}: read the desired set, diff it
 * against the world, apply only the diff, idempotent + self-healing, never
 * hard-fail. Concrete subclasses bind the platform role + breaker + homeserver verb
 * (akkoma for ROLE_MASTODON, tuwunel for ROLE_MATRIX) and the {@code @Scheduled}
 * tick.
 *
 * <p>The homeserver legs are a SEAM, not a requirement: a platform role with no
 * downstream service at all ({@link MeshAccessSyncAction}) satisfies them with an
 * unconditional OK and overrides {@link #revokeCoarseBearer} to a no-op, so its
 * enforcement collapses to the Casdoor role-membership diff this class already
 * performs. That is the whole point of putting the diff here rather than in the
 * concrete actions.
 *
 * <p>Per role, the desired-active membership is
 * {@code CasdoorMembers(role) MINUS active-suspensions}. The action:
 * <ol>
 *   <li>SUSPENDS the homeserver account for every active suspension on this role
 *       (fail-safe leg first), then drops the Casdoor role membership LAST (a failed
 *       trailing leg leaves the user MORE restricted);</li>
 *   <li>for any Casdoor member NOT suspended, ensures the homeserver account is
 *       active (un-stub no-ops; restores a stray suspension).</li>
 * </ol>
 *
 * <p>SINGLE-WRITER: every tick first checks {@link LeaderElection#isLeader()} and
 * skips entirely when not the leader, so only one replica ever writes Casdoor / the
 * homeserver. The {@link CasdoorAdminClient} is {@code @Nullable} (absent unless
 * {@code casdoor.admin.enabled}) — when null the Casdoor leg is skipped and only the
 * homeserver stub-seam runs, so a Casdoor-less dev run still exercises the loop.
 */
abstract class AbstractAccessSyncAction {

    protected final Logger log = LoggerFactory.getLogger(getClass());

    @Nullable
    protected final CasdoorAdminClient casdoor;
    protected final HomeserverAdminClient homeserver;
    protected final AccessSuspensionRepository repo;
    protected final LeaderElection leader;
    protected final GatewayRevocationClient gatewayRevocation;

    protected AbstractAccessSyncAction(@Nullable CasdoorAdminClient casdoor,
                                       HomeserverAdminClient homeserver,
                                       AccessSuspensionRepository repo,
                                       LeaderElection leader,
                                       GatewayRevocationClient gatewayRevocation) {
        this.casdoor = casdoor;
        this.homeserver = homeserver;
        this.repo = repo;
        this.leader = leader;
        this.gatewayRevocation = gatewayRevocation;
    }

    /** The platform role this action reconciles (e.g. ROLE_MATRIX). */
    protected abstract String role();

    /** The homeserver platform name for revocation key construction ({@code matrix} or {@code mastodon}). */
    protected abstract String platform();

    /** Suspend the homeserver account for a localpart (akkoma suspend / tuwunel deactivate). */
    protected abstract Mono<HomeserverOutcome> suspendHomeserver(String localpart);

    /** Restore the homeserver account for a localpart (akkoma unsuspend / tuwunel activate). */
    protected abstract Mono<HomeserverOutcome> activateHomeserver(String localpart);

    /**
     * One reconcile pass for this platform role. Leader-gated; idempotent. Returns
     * normally even on partial failure (the loop is the backstop). Concrete classes
     * wrap this in {@code @CircuitBreaker(name=...)} so a stalled homeserver/Casdoor
     * opens the breaker and the next tick retries.
     */
    protected Mono<Void> reconcile() {
        if (!leader.isLeader()) {
            log.debug("[access-sync {}] not leader ({}) — skipping tick", role(), leader.label());
            return Mono.empty();
        }
        Mono<List<AccessSuspension>> active = repo.activeByRole(role()).collectList();
        Mono<List<String>> members = casdoorMembers();
        return Mono.zip(active, members)
                .flatMap(t -> applyDiff(t.getT1(), t.getT2()))
                .onErrorResume(e -> {
                    log.warn("[access-sync {}] tick failed (will retry next tick): {}", role(), e.toString());
                    return Mono.empty();
                });
    }

    /**
     * Apply the desired state: suspend each active-suspension localpart on the
     * homeserver + drop its Casdoor role (fail-safe order), and re-activate any
     * Casdoor member that is NOT suspended.
     */
    private Mono<Void> applyDiff(List<AccessSuspension> active, List<String> members) {
        Set<String> suspendedLocalparts = new HashSet<>();
        for (AccessSuspension s : active) suspendedLocalparts.add(s.localpart());

        // 1) Enforce every active suspension: homeserver suspend FIRST, Casdoor drop LAST.
        Mono<Void> enforce = Flux.fromIterable(active)
                .concatMap(this::enforceSuspension)
                .then();

        // 2) Re-activate any current Casdoor member that is NOT under an active
        //    suspension (heals a stray homeserver-suspended account). The desired set
        //    is members MINUS suspended.
        Mono<Void> heal = Flux.fromIterable(members)
                .map(m -> ServiceTokenBroker.matrixUser(SuspensionService.localpartSeed(m)))
                .filter(lp -> !suspendedLocalparts.contains(lp))
                .distinct()
                // Fold to the platform-specific homeserver form ONLY for the effect call; the
                // suspended-set check above stays in matrixUser form on both sides.
                .concatMap(lp -> activateHomeserver(effectLocalpart(lp)))
                .then();

        return enforce.then(heal);
    }

    /**
     * Map the STORED suspension localpart (always {@code matrixUser(localpartSeed(handle))} —
     * keeps {@code .-=/}, no length cap; see {@link SuspensionService#suspend}) to the
     * platform-specific homeserver fold the account was actually MINTED under, for the
     * homeserver suspend/activate + coarse gateway-revoke EFFECT legs.
     *
     * <p>Identity for Matrix (the tuwunel account IS the {@code matrixUser} form). Overridden for
     * Mastodon to {@link ServiceTokenBroker#mastodonLocalpart} ({@code .-=/}→{@code _}, 30-char
     * cap) — the same fold {@code ServiceTokenBroker.mastodonToken} mints the akkoma account under
     * and that {@code account.mastodon_localpart} (Liquibase 291) records. Without this, a handle
     * whose two folds differ (dotted Gmail {@code alice.smith}, hyphens, {@code =}/{@code /},
     * {@code >30} chars) has its akkoma deactivate target a NONEXISTENT nickname (real account
     * never suspended) and its coarse key {@code hs:mastodon:<matrix-form>} never equal the
     * gateway's {@code hs:mastodon:<mastodon-form>} (existing bearer never revoked). The
     * suspended-SET membership check stays in {@code matrixUser} form on both sides, so only the
     * outward effect is folded.
     */
    protected String effectLocalpart(String storedLocalpart) {
        return storedLocalpart;
    }

    /**
     * Fail-safe BAN ordering for one active suspension:
     * <ol>
     *   <li>Suspend the homeserver account (the real-fast leg);</li>
     *   <li>POST a coarse revocation key ({@code hs:<platform>:<localpart>}) to the
     *       gateway so every bearer token for this localpart is denied at the filter,
     *       regardless of which device or app minted it (best-effort — never fails the
     *       suspension);</li>
     *   <li>Drop the Casdoor role membership LAST (JWT-leg enforcement).</li>
     * </ol>
     *
     * <p>The Casdoor drop is applied EVERY tick an active suspension exists — that is
     * what self-heals a concurrent grant clobber. The gateway revocation write is also
     * idempotent (a duplicate INSERT simply refreshes the TTL). The homeserver leg's
     * outcome only sets propagation_state (a stubbed/degraded leg keeps the row
     * {@code pending}/{@code failed} so a later tick re-applies it); a failed trailing
     * role-drop is retried next tick (the row stays active), so the user is never LESS
     * restricted than the desired state.
     */
    private Mono<Void> enforceSuspension(AccessSuspension s) {
        // The homeserver account + its brokered token are registered under the platform-specific
        // fold (see effectLocalpart), NOT the stored matrixUser form, so the homeserver-suspend and
        // the coarse gateway key MUST target that fold or a dotted/hyphenated/>30-char handle's real
        // Mastodon account is never suspended and its hs:mastodon:<localpart> key never matches.
        String hsLocalpart = effectLocalpart(s.localpart());
        return suspendHomeserver(hsLocalpart)
                .flatMap(outcome ->
                        // Gateway coarse revoke: best-effort, never blocks the suspension.
                        revokeCoarseBearer(hsLocalpart, s.reason())
                                // Subject revoke: invalidates the custody JWT for this user so
                                // a revoked role cannot be exercised via a stale in-flight JWT.
                                // TTL ≥ custody JWT lifetime (default 3 600 s).
                                .then(gatewayRevocation.revokeSubject(casdoorUsernameOf(s.casdoorUser()),
                                        s.reason(), 3_600L))
                                .then(dropRole(s.casdoorUser()))    // JWT-leg: always drop
                                .then(repo.updatePropagationState(s.id(), propagationFor(outcome)))
                                .then());
    }

    /**
     * The COARSE bearer-revocation leg of a ban: write the gateway revocation key
     * {@code hs:<platform>:<localpart>} so EVERY homeserver-minted bearer token for this
     * localpart is denied at the gateway filter, whichever device or app minted it (the
     * per-token {@code hs_tokens} table is the fine-grained twin). Best-effort — the key
     * is a fast-path propagation of a ban whose authoritative record is already the
     * access_suspension row.
     *
     * <p>{@code 0L} takes the revocation table's default TTL (30 days), which matches the
     * {@code hs_tokens} TTL so the key outlives any token it gates.
     *
     * <p>SEAM: the key namespace only means anything for a platform whose HOMESERVER
     * mints bearer tokens the gateway resolves back to a localpart. A role with no
     * downstream service ({@link MeshAccessSyncAction}) overrides this to a no-op rather
     * than writing an {@code hs:} key nothing can ever match — the subject revoke +
     * Casdoor role drop below are its whole enforcement.
     */
    protected Mono<Void> revokeCoarseBearer(String hsLocalpart, String reason) {
        return gatewayRevocation.revokeCoarse(platform(), hsLocalpart, reason, 0L);
    }

    private static String propagationFor(HomeserverOutcome outcome) {
        if (outcome.isOk()) return AccessSuspension.PROP_APPLIED;
        if (outcome.isStubbed()) return AccessSuspension.PROP_PENDING;
        return AccessSuspension.PROP_FAILED;
    }

    // ── Casdoor single-writer legs (the ONLY caller of add/removeUserFromRole) ──
    protected Mono<List<String>> casdoorMembers() {
        return (casdoor == null) ? Mono.just(List.of()) : casdoor.getRoleMembers(role());
    }

    /** Normalize a free-text casdoorUser (bare username / provider:handle / org/username —
     *  see SuspensionService#localpartSeed) to the bare Casdoor USERNAME the gateway's
     *  RevocationGatewayFilter matches via Roles.casdoorIdOf(jwt) (jwt sub). Mirrors
     *  AdminController#revokeOnDisable (CasdoorAdminClient.usernameOf(provider, handle))
     *  and AuthController#revokeSubject's provider-default-to-"google" convention for an
     *  unprefixed identifier. */
    private static String casdoorUsernameOf(String casdoorUser) {
        if (casdoorUser == null) return null;
        String s = casdoorUser;
        int slash = s.lastIndexOf('/');
        if (slash >= 0) s = s.substring(slash + 1);
        int colon = s.indexOf(':');
        String provider = colon >= 0 ? s.substring(0, colon) : "google";
        String handle = colon >= 0 ? s.substring(colon + 1) : s;
        return CasdoorAdminClient.usernameOf(provider, handle);
    }

    protected Mono<Void> dropRole(String casdoorUser) {
        if (casdoor == null) return Mono.empty();
        return casdoor.removeUserFromRole(role(), userIdFor(casdoorUser))
                .onErrorResume(e -> {
                    log.warn("[access-sync {}] removeUserFromRole {} failed (retry next tick): {}",
                            role(), casdoorUser, e.toString());
                    return Mono.empty();
                });
    }

    protected Mono<Void> addRole(String casdoorUser) {
        if (casdoor == null) return Mono.empty();
        return casdoor.addUserToRole(role(), userIdFor(casdoorUser))
                .onErrorResume(e -> {
                    log.warn("[access-sync {}] addUserToRole {} failed (retry next tick): {}",
                            role(), casdoorUser, e.toString());
                    return Mono.empty();
                });
    }

    /**
     * The Casdoor member id ({@code org/username}) for a grantee. If already in
     * {@code org/username} form it is passed through; otherwise the free-text
     * casdoorUser (bare username OR {@code provider:handle}) is normalized via
     * {@link #casdoorUsernameOf} — the SAME fold the account was minted under —
     * before being prefixed with the client's organization. Without this, a
     * {@code provider:handle}-form casdoorUser (a first-class input shape, see
     * SuspensionService#localpartSeed) produced a member id Casdoor's role-members
     * list never contains, so add/removeUserFromRole silently no-op'd forever.
     */
    protected String userIdFor(String casdoorUser) {
        if (casdoorUser == null) return null;
        if (casdoorUser.contains("/")) return casdoorUser;
        String org = casdoor == null ? "hugmesh" : casdoor.organization();
        return org + "/" + casdoorUsernameOf(casdoorUser);
    }
}
