package net.hugmesh.adminbff.suspension;

import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import io.github.resilience4j.circuitbreaker.annotation.CircuitBreaker;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;
import net.hugmesh.adminbff.federation.FederationOverrideClearClient;
import net.hugmesh.adminbff.homeserver.HomeserverAdminClient;
import net.hugmesh.adminbff.homeserver.HomeserverOutcome;
import net.hugmesh.adminbff.lease.LeaderElection;
import net.hugmesh.adminbff.provision.ServiceTokenBroker;
import net.hugmesh.authcore.casdoor.CasdoorAdminClient;
import net.hugmesh.authcore.provision.GatewayRevocationClient;

import java.time.Instant;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Auto-restores timed suspensions at TTL — the single clock. On each tick it scans
 * {@code expires_at <= now AND state='active' AND restore_role}, and for each row:
 *
 * <ol>
 *   <li>CASes {@code active -> restored} ({@link AccessSuspensionRepository#markRestored});
 *       only the writer that wins the transition (rows-updated == 1) proceeds, so a
 *       second replica/tick never double-restores;</li>
 *   <li>FAIL-SAFE ordering — re-activates the homeserver account FIRST (akkoma
 *       unsuspend / tuwunel activate), then re-adds the Casdoor role LAST. If the
 *       trailing role-add fails it is retried by the per-platform reconcile loop
 *       (which adds the role for any non-suspended member), so the row never
 *       reverts to a silent permanent ban.</li>
 * </ol>
 *
 * <p>Single-writer via {@link LeaderElection} + the markRestored CAS. Survives
 * restarts: the scan re-selects every overdue row on boot. Circuit breaker
 * {@code casdoor} (reused). Permanent bans (expires_at NULL / restore_role=false) are
 * excluded by {@code dueForRestore} and never auto-restore.
 *
 * <p>PROFILE suspensions have no homeserver leg and no Casdoor-role flip; their
 * effect is a federation {@code scope=user} kill override tagged
 * {@code reason='access_suspension:<id>'}. At PROFILE-scope expiry this action now
 * fires the federation restore leg too — it calls federation-api
 * {@code POST /overrides/clear-source} with that exact source tag (via
 * {@link FederationOverrideClearClient}) so the suspended owner's modules return on
 * the next manifest render. ADDITIVE + best-effort: it fires ONLY at PROFILE-scope
 * expiry, is a no-op when no matching override exists (federation returns 0 cleared),
 * and any failure is swallowed (the row is already CASed to {@code restored} and the
 * federation read path self-heals).
 */
@Service
@SuppressFBWarnings(value = "EI_EXPOSE_REP2",
        justification = "Spring constructor injection: the container owns this singleton collaborator and it is never mutated by this class after construction; a defensive copy of a bean is meaningless (not caller-owned mutable data).")
public class SuspensionExpiryAction {

    private static final Logger log = LoggerFactory.getLogger(SuspensionExpiryAction.class);

    @Nullable
    private final CasdoorAdminClient casdoor;
    private final HomeserverAdminClient homeserver;
    private final AccessSuspensionRepository repo;
    private final LeaderElection leader;
    private final GatewayRevocationClient gatewayRevocation;
    private final FederationOverrideClearClient federationOverrideClear;

    private final AtomicReference<Instant> lastSuccessAt = new AtomicReference<>(Instant.EPOCH);

    public SuspensionExpiryAction(@Nullable CasdoorAdminClient casdoor,
                                  HomeserverAdminClient homeserver,
                                  AccessSuspensionRepository repo,
                                  LeaderElection leader,
                                  GatewayRevocationClient gatewayRevocation,
                                  FederationOverrideClearClient federationOverrideClear) {
        this.casdoor = casdoor;
        this.homeserver = homeserver;
        this.repo = repo;
        this.leader = leader;
        this.gatewayRevocation = gatewayRevocation;
        this.federationOverrideClear = federationOverrideClear;
    }

    public Instant lastSuccessAt() {
        return lastSuccessAt.get();
    }

    @Scheduled(
            fixedDelayString = "${app.access-suspension.expiry.interval-ms:10000}",
            initialDelayString = "${app.access-suspension.expiry.initial-delay-ms:12000}")
    public void runTick() {
        runOnce()
                .doOnSuccess(v -> lastSuccessAt.set(Instant.now()))
                .onErrorResume(e -> Mono.empty())
                .subscribe();
    }

    @CircuitBreaker(name = "casdoor")
    public Mono<Void> runOnce() {
        if (!leader.isLeader()) {
            log.debug("[suspension-expiry] not leader ({}) — skipping tick", leader.label());
            return Mono.empty();
        }
        return repo.dueForRestore(Instant.now())
                .concatMap(this::restore)
                .then()
                .onErrorResume(e -> {
                    log.warn("[suspension-expiry] tick failed (will retry next tick): {}", e.toString());
                    return Mono.empty();
                });
    }

    /**
     * Restore one due suspension. CAS-guard first; only the winner:
     * <ol>
     *   <li>Re-activates the homeserver account (fail-safe: un-restrict first);</li>
     *   <li>Clears the coarse gateway revocation key ({@code hs:<platform>:<localpart>})
     *       so gateway bearers are no longer blocked (best-effort);</li>
     *   <li>Re-adds the Casdoor role;</li>
     *   <li>For a PROFILE-scope row ONLY, re-arms the federation {@code scope=user}
     *       kill override created for this suspension (best-effort, last).</li>
     * </ol>
     */
    Mono<Void> restore(AccessSuspension s) {
        return repo.markRestored(s.id())
                // CAS guard: only the winning replica executes the restore actions.
                .flatMap(rows -> restoreIfWon(rows, s));
    }

    /**
     * PROFILE-scope restore leg: re-arm the federation {@code scope=user} kill override
     * created for this suspension. The override was written federation-side tagged
     * {@code reason='access_suspension:<id>'}, so clearing BY SOURCE with that exact tag
     * re-arms ONLY this user's row (the source is a globally-unique id). ADDITIVE: only
     * PROFILE rows ever had a federation override, so platform-role rows skip this leg.
     * Best-effort — {@link FederationOverrideClearClient#clearSource} swallows errors and
     * is a no-op when no matching override exists.
     */
    /** Execute restore actions only when this replica won the CAS (rows > 0). */
    private Mono<Void> restoreIfWon(Long rows, AccessSuspension s) {
        if (rows == null || rows == 0) {
            // Another tick/replica already restored this row — nothing to do.
            return Mono.empty();
        }
        log.info("[suspension-expiry] restoring {} for {} (id={})", s.role(), s.casdoorUser(), s.id());
        return activateHomeserver(s)              // FAIL-SAFE: un-restrict first
                .then(clearGatewayRevocation(s)) // lift the coarse ban key
                .then(reAddRole(s))              // re-add the role
                .then(clearFederationOverride(s)); // PROFILE-scope only, last
    }

    private Mono<Void> clearFederationOverride(AccessSuspension s) {
        if (!AccessSuspension.ROLE_PROFILE.equals(s.role())) {
            return Mono.empty(); // platform-role suspensions have no federation override
        }
        return federationOverrideClear.clearSource("access_suspension:" + s.id());
    }

    /**
     * Lift the coarse gateway revocation key for ROLE_MATRIX and ROLE_MASTODON.
     * Best-effort: errors are swallowed by {@link GatewayRevocationClient#clearCoarse}.
     */
    private Mono<Void> clearGatewayRevocation(AccessSuspension s) {
        return switch (s.role()) {
            case AccessSuspension.ROLE_MATRIX -> gatewayRevocation.clearCoarse("matrix", s.localpart());
            case AccessSuspension.ROLE_MASTODON -> gatewayRevocation.clearCoarse("mastodon", effectLocalpart(s));
            default -> Mono.empty(); // PROFILE has no homeserver revocation key
        };
    }

    private Mono<HomeserverOutcome> activateHomeserver(AccessSuspension s) {
        return switch (s.role()) {
            case AccessSuspension.ROLE_MATRIX -> homeserver.activateMatrix(s.localpart());
            case AccessSuspension.ROLE_MASTODON -> homeserver.unsuspendMastodon(effectLocalpart(s));
            // PROFILE has no homeserver account state; the federation_override clear
            // is a later-phase seam. Treat as OK so the role re-add proceeds.
            default -> Mono.just(HomeserverOutcome.ok());
        };
    }

    /** Fold the stored (matrixUser-form) localpart to the platform's actual homeserver
     *  form for the two EFFECT calls (homeserver reactivate + coarse gateway-key clear) —
     *  mirrors AbstractAccessSyncAction#effectLocalpart / MastodonAccessSyncAction's override.
     *  The restore leg must target the SAME folded account the suspend leg suspended. */
    private static String effectLocalpart(AccessSuspension s) {
        return AccessSuspension.ROLE_MASTODON.equals(s.role())
                ? ServiceTokenBroker.mastodonLocalpart(s.localpart())
                : s.localpart();
    }

    private Mono<Void> reAddRole(AccessSuspension s) {
        // PROFILE is not a Casdoor-role flip (it is a federation override) — nothing
        // to re-add in Casdoor for it.
        if (casdoor == null || AccessSuspension.ROLE_PROFILE.equals(s.role())) {
            return Mono.empty();
        }
        return casdoor.addUserToRole(s.role(), userIdFor(s.casdoorUser()))
                .onErrorResume(e -> {
                    // The per-platform reconcile loop re-adds the role for any
                    // non-suspended member, so a failed add here is self-healing.
                    log.warn("[suspension-expiry] re-add role {} for {} failed (loop will heal): {}",
                            s.role(), s.casdoorUser(), e.toString());
                    return Mono.empty();
                });
    }

    /**
     * The Casdoor member id ({@code org/username}) for a grantee. If already in
     * {@code org/username} form it is passed through; otherwise the free-text
     * casdoorUser (bare username OR {@code provider:handle}) is normalized via
     * {@link #casdoorUsernameOf} — the SAME fold the account was minted under —
     * before being prefixed with the client's organization. Mirrors
     * AbstractAccessSyncAction's identical helper (this class does not extend it).
     */
    private String userIdFor(String casdoorUser) {
        if (casdoorUser == null) return null;
        if (casdoorUser.contains("/")) return casdoorUser;
        String org = casdoor == null ? "hugmesh" : casdoor.organization();
        return org + "/" + casdoorUsernameOf(casdoorUser);
    }

    /** See AbstractAccessSyncAction#casdoorUsernameOf — duplicated here since this
     *  class does not share a base class with the access-sync actions. */
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
}
