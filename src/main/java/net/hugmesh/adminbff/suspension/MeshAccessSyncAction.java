package net.hugmesh.adminbff.suspension;

import io.github.resilience4j.circuitbreaker.annotation.CircuitBreaker;
import org.jspecify.annotations.Nullable;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;
import net.hugmesh.adminbff.homeserver.HomeserverAdminClient;
import net.hugmesh.adminbff.homeserver.HomeserverOutcome;
import net.hugmesh.adminbff.lease.LeaderElection;
import net.hugmesh.authcore.casdoor.CasdoorAdminClient;
import net.hugmesh.authcore.provision.GatewayRevocationClient;

import java.time.Instant;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Reconciles ROLE_MESH: drives the Casdoor membership of the mesh access role from the
 * access_suspension desired state. Single-writer via the injected {@link LeaderElection}.
 *
 * <p><b>Why there is NO downstream service leg (deliberate, not a stub).</b> Its two
 * siblings each drive a homeserver as well as Casdoor — {@link MatrixAccessSyncAction}
 * deactivates the tuwunel account, {@link MastodonAccessSyncAction} suspends the akkoma
 * account — because for those platforms the Casdoor role only gates the GATEWAY, while
 * the account and its long-lived homeserver tokens keep working underneath it. ROLE_MESH
 * has no such underneath: there is no mesh homeserver, no mesh-minted bearer token and no
 * mesh-side account state. The role IS the whole grant — it is the gateway route-access
 * FLOOR for {@code /bff/mesh/**}, and by the gateway's canonical-seed rule a ban is role
 * removal, which makes every allow-predicate on those routes false, leaving the surface
 * governed-but-ungranted, which is DENY. So the Casdoor role-membership drop this class
 * performs is not a partial enforcement awaiting a second leg; it is the complete one.
 *
 * <p>Concretely, that shapes three things:
 * <ul>
 *   <li>{@link #suspendHomeserver} / {@link #activateHomeserver} return an unconditional
 *       {@link HomeserverOutcome#ok()} — NOT the {@code STUBBED} outcome a gated-but-real
 *       seam returns. STUBBED means "the effect is pending, re-apply it next tick" and
 *       would park every mesh row on {@code propagation_state='pending'} forever; OK is
 *       the truth here, so a mesh row settles on {@code 'applied'} once the role is
 *       actually dropped.</li>
 *   <li>{@link #revokeCoarseBearer} is overridden to a no-op: the coarse key namespace
 *       {@code hs:<platform>:<localpart>} is matched against HOMESERVER-minted bearers by
 *       the gateway's {@code HomeserverTokenRevocationFilter}, so an {@code hs:mesh:…} key
 *       would be a row nothing can ever match — 30 days of dead weight per mesh ban. The
 *       SUBJECT revoke the base class writes next is the one that matters: it denies the
 *       user's in-flight custody JWT (which still carries ROLE_MESH for up to its ~1 h
 *       lifetime) so the ban bites immediately rather than at token expiry.</li>
 *   <li>Circuit breaker {@code casdoor} rather than a platform-named one: Casdoor is the
 *       ONLY external dependency of this reconcile, so it is the only thing that can
 *       stall it. Same reuse {@link SuspensionExpiryAction} makes for the same reason —
 *       no new resilience4j instance is needed in application.yml.</li>
 * </ul>
 *
 * <p>Everything else — the desired-set diff, the fail-safe ordering, the self-heal of a
 * concurrent Casdoor grant clobber, the leader gate — is inherited unchanged.
 *
 * @see AbstractAccessSyncAction for the shared reconcile shape (GameMasterAdminSyncAction-derived)
 */
@Service
public class MeshAccessSyncAction extends AbstractAccessSyncAction {

    private final AtomicReference<Instant> lastSuccessAt = new AtomicReference<>(Instant.EPOCH);

    public MeshAccessSyncAction(@Nullable CasdoorAdminClient casdoor,
                                HomeserverAdminClient homeserver,
                                AccessSuspensionRepository repo,
                                LeaderElection leader,
                                GatewayRevocationClient gatewayRevocation) {
        super(casdoor, homeserver, repo, leader, gatewayRevocation);
    }

    @Override
    protected String role() {
        return AccessSuspension.ROLE_MESH;
    }

    /**
     * The revocation-key namespace this platform would use. Retained for the base
     * contract only — {@link #revokeCoarseBearer} never dials the gateway for ROLE_MESH,
     * so no {@code hs:mesh:*} key is ever written. Kept honest (rather than throwing) so
     * a future mesh service that DOES mint its own bearers can simply drop the override.
     */
    @Override
    protected String platform() {
        return "mesh";
    }

    /**
     * No mesh homeserver exists, so there is no account state to suspend: the ban is
     * carried entirely by the Casdoor role drop the base class performs next. Returns
     * OK (not STUBBED) so {@code propagation_state} settles on {@code 'applied'} — see
     * the class doc.
     */
    @Override
    protected Mono<HomeserverOutcome> suspendHomeserver(String localpart) {
        return Mono.just(HomeserverOutcome.ok());
    }

    /**
     * Counterpart of {@link #suspendHomeserver} for the heal leg (re-activate any Casdoor
     * member NOT under an active suspension): nothing downstream to re-activate, so the
     * heal pass for ROLE_MESH is a pure no-op over the non-suspended members.
     */
    @Override
    protected Mono<HomeserverOutcome> activateHomeserver(String localpart) {
        return Mono.just(HomeserverOutcome.ok());
    }

    /**
     * ROLE_MESH mints no homeserver bearer token, so the coarse {@code hs:mesh:<localpart>}
     * gateway key would never match anything the {@code HomeserverTokenRevocationFilter}
     * resolves. Skip it — the base class's SUBJECT revoke (which denies the stale custody
     * JWT still carrying ROLE_MESH) plus the Casdoor role drop are the complete ban.
     */
    @Override
    protected Mono<Void> revokeCoarseBearer(String hsLocalpart, String reason) {
        return Mono.empty();
    }

    public Instant lastSuccessAt() {
        return lastSuccessAt.get();
    }

    @Scheduled(
            fixedDelayString = "${app.access-suspension.reconcile.interval-ms:30000}",
            initialDelayString = "${app.access-suspension.reconcile.initial-delay-ms:15000}")
    public void runTick() {
        runOnce()
                .doOnSuccess(v -> lastSuccessAt.set(Instant.now()))
                .onErrorResume(e -> Mono.empty())
                .subscribe();
    }

    @CircuitBreaker(name = "casdoor")
    public Mono<Void> runOnce() {
        return reconcile();
    }
}
