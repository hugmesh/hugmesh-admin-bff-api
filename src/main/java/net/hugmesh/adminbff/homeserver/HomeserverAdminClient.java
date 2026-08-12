package net.hugmesh.adminbff.homeserver;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

import java.util.Map;

/**
 * Shared homeserver account-state admin client — the SINGLE GATED STUB-SEAM the
 * access_suspension reconcile loop calls to drive a Matrix/Mastodon account
 * active/suspended on the real homeservers:
 *
 * <ul>
 *   <li><b>akkoma</b> (the Mastodon-API server): {@link #suspendMastodon} /
 *       {@link #unsuspendMastodon} — WIRED-REAL (gated). Idempotent batch verbs
 *       {@code PATCH /api/v1/pleroma/admin/users/deactivate} (and {@code /activate})
 *       with body {@code {"nicknames":[localpart]}}, admin bearer over the mTLS
 *       sidecar. (Pleroma/Akkoma has NO {@code /users/{nick}/suspend} verb, and
 *       {@code toggle_activation} is a FLIP unsafe in a reconcile loop — see the seam
 *       javadoc.)</li>
 *   <li><b>tuwunel</b> (the Conduit-family Matrix server, which has NO REST admin
 *       API): {@link #deactivateMatrix} / {@link #activateMatrix} — FLAG-GATED
 *       STRUCTURED STUB. The only transport is an admin-room bot command
 *       {@code !admin users deactivate @localpart:server} posted as an
 *       {@code m.room.message}; the HTTP 200 only ACKs the post, not the effect, so a
 *       real wire-up needs a persistent Matrix identity + async reply correlation —
 *       disproportionate, and there is NO {@code activate} command at all. Left
 *       STUBBED on purpose (never hard-fail) — see the seam javadoc.</li>
 * </ul>
 *
 * <p>This mirrors the hugmesh-mod-bff-api {@code MastodonAdminClient} /
 * {@code MatrixAdminClient} + {@code ExternalAdminConfig} stub-seam pattern and the
 * admin-bff {@code AnnouncementMastodonClient} pattern EXACTLY:
 *
 * <h3>Gated external call — honest, SAFE deferral</h3>
 * <ul>
 *   <li>the reactive {@link WebClient}s are built + ready
 *       ({@link #akkoma}/{@link #tuwunel});</li>
 *   <li>gated by {@code homeserver.admin.enabled} (default false) so an akkoma /
 *       tuwunel-less dev/test/CI run boots clean. When DISABLED every seam returns
 *       {@link HomeserverOutcome#stubbed()} after logging the intended verb — a no-flag
 *       cluster is a guaranteed no-op;</li>
 *   <li>when ENABLED: the akkoma suspend/unsuspend legs issue the REAL idempotent
 *       PATCH; the tuwunel legs STAY STUBBED (the admin-room transport is out of scope
 *       — see {@link #doTuwunelDeactivate});</li>
 *   <li>it NEVER hard-fails: an attempted-and-failed call resolves to
 *       {@link HomeserverOutcome#degraded} so the reconcile tick continues and the
 *       desired-state row remains the authority (re-applied next tick).</li>
 * </ul>
 *
 * <p>The admin bearer is sourced from Vault {@code hugmesh/akkoma-admin}
 * property {@code token} via the ESO {@code akkoma-admin} ExternalSecret, injected as
 * {@code homeserver.admin.akkoma-token} (placeholder-only; never inline). When blank
 * (the default/dev case) no {@code Authorization} header is sent.
 */
public class HomeserverAdminClient {

    private static final Logger log = LoggerFactory.getLogger(HomeserverAdminClient.class);

    private final WebClient akkoma;
    @SuppressWarnings("PMD.UnusedPrivateField") // retained for future tuwunel admin API dial
    private final WebClient tuwunel;
    private final boolean enabled;
    /**
     * The akkoma privileged admin bearer (Vault {@code hugmesh/akkoma-admin}
     * property {@code token} via the ESO {@code akkoma-admin} ExternalSecret), injected
     * as {@code homeserver.admin.akkoma-token}. Placeholder-only — NEVER inline. When
     * blank no {@code Authorization} header is added (the dev/test default), so the
     * recording-ExchangeFunction tests can exercise the real call shape without a token.
     */
    private final String akkomaToken;
    /**
     * SEPARATE gate for the DOMAIN-LOCK (force-local / no-federation) seams below,
     * independent of the suspend gate {@link #enabled}. SHIPS DARK: default off
     * ({@code homeserver.domainlock.enabled=false}) so the domain-lock role can land
     * safely without advertising the homeserver/egress effect as enforced. The
     * desired-state table + service + reconcile + delegation are the real deliverable;
     * the force-local effect stays a STUBBED seam (never hard-fail) until the generator
     * akkoma-MRF image + egress policy are real. Until then the role is DEGRADED
     * (BFF/UI/allowlist only) exactly as documented in the design's mergeSequencing.
     */
    private final boolean domainLockEnabled;

    public HomeserverAdminClient(WebClient akkoma, WebClient tuwunel, boolean enabled) {
        this(akkoma, tuwunel, enabled, false);
    }

    public HomeserverAdminClient(WebClient akkoma, WebClient tuwunel, boolean enabled,
                                 boolean domainLockEnabled) {
        this(akkoma, tuwunel, enabled, domainLockEnabled, null);
    }

    public HomeserverAdminClient(WebClient akkoma, WebClient tuwunel, boolean enabled,
                                 boolean domainLockEnabled, String akkomaToken) {
        this.akkoma = akkoma;
        this.tuwunel = tuwunel;
        this.enabled = enabled;
        this.domainLockEnabled = domainLockEnabled;
        this.akkomaToken = akkomaToken;
    }

    public boolean enabled() {
        return enabled;
    }

    public boolean domainLockEnabled() {
        return domainLockEnabled;
    }

    /**
     * Runtime seam-real signal for the domain-lock force-local legs (the B4
     * prod-hygiene gate consumes this — a manifest scan cannot see a Java stub body).
     * {@code false} = the seam is a STUB (config off, OR enabled-but-not-yet-wired);
     * {@code true} = the real homeserver/egress force-local call is wired. Today the
     * seam is always stubbed, so this is always {@code false} until the real
     * {@code doAkkomaForceLocal}/{@code doTuwunelFederationLock} bodies land.
     */
    public boolean domainLockSeamReal() {
        return false;
    }

    // ── akkoma (Mastodon) ──────────────────────────────────────────────
    /** Suspend (make unreachable) the akkoma account for {@code localpart}. */
    public Mono<HomeserverOutcome> suspendMastodon(String localpart) {
        log.info("[akkoma] suspend account '{}' (enabled={})", localpart, enabled);
        return doAkkomaSuspend(localpart, true);
    }

    /** Unsuspend (restore) the akkoma account for {@code localpart}. */
    public Mono<HomeserverOutcome> unsuspendMastodon(String localpart) {
        log.info("[akkoma] unsuspend account '{}' (enabled={})", localpart, enabled);
        return doAkkomaSuspend(localpart, false);
    }

    // ── tuwunel (Matrix) ───────────────────────────────────────────────
    /** Deactivate (make unreachable) the tuwunel account for {@code localpart}. */
    public Mono<HomeserverOutcome> deactivateMatrix(String localpart) {
        log.info("[tuwunel] deactivate account '{}' (enabled={})", localpart, enabled);
        return doTuwunelDeactivate(localpart, true);
    }

    /** Re-activate (restore) the tuwunel account for {@code localpart}. */
    public Mono<HomeserverOutcome> activateMatrix(String localpart) {
        log.info("[tuwunel] activate account '{}' (enabled={})", localpart, enabled);
        return doTuwunelDeactivate(localpart, false);
    }

    // ── single external-call seams ─────────────────────────────────────
    /**
     * The akkoma suspend/unsuspend seam — WIRED-REAL behind {@link #enabled}.
     *
     * <p>Uses the CONFIRMED Pleroma/Akkoma pleroma-admin batch verbs, which are
     * IDEMPOTENT absolute sets (NOT the non-existent {@code /users/{nick}/suspend}, and
     * NOT {@code toggle_activation} which is a flip that breaks a reconcile loop):
     * <ul>
     *   <li>suspend → {@code PATCH /api/v1/pleroma/admin/users/deactivate}</li>
     *   <li>unsuspend → {@code PATCH /api/v1/pleroma/admin/users/activate}</li>
     * </ul>
     * both with body {@code {"nicknames":[localpart]}} (a JSON array even for one user)
     * and the admin bearer over the akkoma-proxy mTLS sidecar. Re-applying the same
     * desired state is a natural 200 no-op, so an already-suspended/already-active user
     * resolves to {@link HomeserverOutcome#ok()} — exactly what the reconcile tick wants.
     *
     * <p>DISABLED ({@code homeserver.admin.enabled=false}) → {@link HomeserverOutcome#stubbed()}
     * with no call. Any transport failure → {@link HomeserverOutcome#degraded} (never
     * hard-fail; the row is re-applied next tick).
     */
    private Mono<HomeserverOutcome> doAkkomaSuspend(String localpart, boolean suspend) {
        if (!enabled) {
            return Mono.just(HomeserverOutcome.stubbed());
        }
        String verb = suspend ? "deactivate" : "activate";
        return akkoma.patch()
                .uri("/api/v1/pleroma/admin/users/{verb}", verb)
                .headers(this::applyAkkomaAuth)
                .bodyValue(Map.of("nicknames", java.util.List.of(localpart)))
                .retrieve()
                .toBodilessEntity()
                .thenReturn(HomeserverOutcome.ok())
                .onErrorResume(e -> {
                    log.warn("[akkoma] {} for '{}' degraded: {}", verb, localpart, e.toString());
                    return Mono.just(HomeserverOutcome.degraded(e.getMessage()));
                });
    }

    /** Add the admin bearer iff a token is configured (placeholder-only; never inline). */
    private void applyAkkomaAuth(org.springframework.http.HttpHeaders h) {
        if (akkomaToken != null && !akkomaToken.isBlank()) {
            h.setBearerAuth(akkomaToken);
        }
    }

    /**
     * The tuwunel deactivate/activate seam — DELIBERATELY a FLAG-GATED STRUCTURED STUB
     * (the recommended posture; do NOT half-build a Matrix client here).
     *
     * <p>tuwunel (Conduit-family) has NO REST admin API. The only admin transport is a
     * text command posted as an {@code m.room.message} into the server admin room
     * {@code #admins:<server>}, which an in-process bot reads and executes, replying
     * ASYNCHRONOUSLY with another room event. Concretely:
     * <pre>{@code
     *   // deactivate ONLY — there is NO "!admin users activate" command in tuwunel:
     *   String cmd = "!admin users deactivate @" + localpart + ":" + serverName;
     *   POST /_matrix/client/v3/rooms/{adminRoomId}/send/m.room.message/{txnId}
     *        Authorization: Bearer <matrix-admin-token>   // Vault hugmesh/tuwunel-admin
     *        {"msgtype":"m.text","body": cmd}
     * }</pre>
     * Wiring this for real requires a persistent logged-in Matrix identity (token
     * lifecycle), admin-room alias→room_id resolution, per-message txn ids, AND async
     * reply correlation (the HTTP 200 ACKs only that the command MESSAGE posted, not the
     * effect) — essentially a small Matrix client, disproportionate for this seam.
     * Re-activation has NO tuwunel command at all, and the authoritative Matrix backstop
     * for suspension is the generator egress NetworkPolicy + the desired-state row. So
     * this seam stays STUBBED (never hard-fail): callers stay pending and the row is
     * authority, ready for a later dedicated Matrix-client PR.
     */
    private Mono<HomeserverOutcome> doTuwunelDeactivate(String localpart, boolean deactivate) {
        if (!enabled) {
            return Mono.just(HomeserverOutcome.stubbed());
        }
        Map<String, Object> intended = Map.of("localpart", localpart,
                "verb", deactivate ? "deactivate" : "activate(no-tuwunel-verb)");
        log.warn("[tuwunel] {} for '{}' is a FLAG-GATED STRUCTURED STUB — tuwunel has no REST "
                + "admin API; the admin-room m.room.message transport needs a persistent Matrix "
                + "client + async reply correlation (out of scope), and there is no 'activate' "
                + "command. egress NetworkPolicy + the desired-state row are authority (intended={})",
                deactivate ? "deactivate" : "activate", localpart, intended);
        return Mono.just(HomeserverOutcome.stubbed());
    }

    // ── @system NOTIFICATION DM (Notifications PR5) ────────────────────────────
    /**
     * Send a NEUTRAL {@code @system} direct message to a tuwunel (Matrix) user
     * {@code localpart} — the Matrix leg of the per-domain {@code @system} notifications
     * sender. Reuses the SAME tuwunel mTLS-sidecar admin-room seam the suspend/lock legs
     * use, gated on the SAME {@link #enabled} suspend gate (the homeserver admin seam is a
     * single switch). STUBBED by default — see {@link #doTuwunelSystemDm}.
     *
     * <p>The {@code body} is the neutral title+body the {@code NotificationTemplate}
     * composed (reason/ttl context, NEVER the acting mod/admin identity).
     */
    public Mono<HomeserverOutcome> sendSystemDirectMessage(String localpart, String body) {
        log.info("[tuwunel] @system DM to '{}' (enabled={})", localpart, enabled);
        return doTuwunelSystemDm(localpart, body);
    }

    /**
     * The tuwunel {@code @system} DM seam. STUBBED by default. tuwunel (Conduit-family)
     * has no REST send API, so the confirmed path is: as the {@code @system} bot, create-
     * or-resolve a DM room with the target localpart and send an {@code m.text} event,
     * over the tuwunel-proxy mTLS sidecar with the {@code @system} access token, roughly:
     * <pre>{@code
     *   // resolve/create the @system<->user DM room then send the neutral text
     *   return tuwunel.post().uri("/_matrix/client/v3/rooms/{room}/send/m.room.message/{txn}", room, txn)
     *       .header("Authorization", "Bearer " + systemToken)
     *       .bodyValue(Map.of("msgtype", "m.text", "body", body))
     *       .retrieve().toBodilessEntity().thenReturn(HomeserverOutcome.ok())
     *       .onErrorResume(e -> Mono.just(HomeserverOutcome.degraded(e.getMessage())));
     * }</pre>
     */
    private Mono<HomeserverOutcome> doTuwunelSystemDm(String localpart, String body) {
        if (!enabled) {
            return Mono.just(HomeserverOutcome.stubbed());
        }
        log.warn("[tuwunel] @system DM to '{}' is STUBBED — the tuwunel @system DM "
                + "room-resolve + send shape/token are unconfirmed; wire the real call in "
                + "doTuwunelSystemDm() before relying on it (body length={})",
                localpart, body == null ? 0 : body.length());
        return Mono.just(HomeserverOutcome.stubbed());
    }

    // ── DOMAIN-LOCK (force local-only / no-federation) seams ───────────────────
    // SEPARATE from suspend/deactivate above: domain-lock KEEPS the account active +
    // KEEPS the gateway role — it only forces the user's traffic LOCAL (no outbound
    // federation). The AUTHORITATIVE enforcement is the generator akkoma-MRF +
    // egress NetworkPolicy reading the domain_lock active set (see DomainLock); these
    // homeserver-side seams are the in-homeserver leg (akkoma per-actor force-local;
    // tuwunel per-instance federation isolation — tuwunel has NO per-user control, so
    // egress is the real Matrix backstop). Gated on the SEPARATE domainLockEnabled.

    /**
     * Force the akkoma account for {@code localpart} into local-only mode (on=true) or
     * release it (on=false). The authoritative enforcer is the generator
     * {@code ForceLocalForUsersPolicy} MRF reading the domain_lock active set; this is
     * the homeserver-side leg.
     */
    public Mono<HomeserverOutcome> forceLocalMastodon(String localpart, boolean on) {
        log.info("[akkoma] force-local '{}' on={} (domainLockEnabled={})", localpart, on, domainLockEnabled);
        return doAkkomaForceLocal(localpart, on);
    }

    /**
     * Engage (on=true) / release (on=false) per-user Matrix federation-lock for
     * {@code localpart}. tuwunel (Conduit-family) has NO per-user federation control —
     * only server-wide {@code forbidden_remote_server_names} /
     * {@code allowed_remote_server_names_experimental} — so the egress NetworkPolicy is
     * the authoritative Matrix backstop; this seam carries the per-instance isolation
     * intent + the at-lock room-hygiene severance.
     */
    public Mono<HomeserverOutcome> federationLockMatrix(String localpart, boolean on) {
        log.info("[tuwunel] federation-lock '{}' on={} (domainLockEnabled={})", localpart, on, domainLockEnabled);
        return doTuwunelFederationLock(localpart, on);
    }

    /**
     * The akkoma force-local seam. STUBBED by default. SHIPS DARK: gated on
     * {@code domainLockEnabled} (default false); even when enabled it stays STUBBED
     * until the generator custom-MRF image is published + the per-actor force-local
     * admin verb is confirmed. The authoritative enforcement is the MRF reading the
     * domain_lock active set, so this homeserver-side call is a best-effort
     * congruence leg — never hard-fail. The confirmed call is roughly (admin bearer
     * over the akkoma-proxy mTLS sidecar):
     * <pre>{@code
     *   // toggle the per-actor force-local marker the ForceLocalForUsersPolicy MRF reads
     *   return akkoma.post()
     *       .uri("/api/v1/pleroma/admin/users/{nick}/force_local", localpart)
     *       .header("Authorization", "Bearer " + adminToken)
     *       .bodyValue(Map.of("force_local", on))
     *       .retrieve().toBodilessEntity().thenReturn(HomeserverOutcome.ok())
     *       .onErrorResume(e -> Mono.just(HomeserverOutcome.degraded(e.getMessage())));
     * }</pre>
     */
    private Mono<HomeserverOutcome> doAkkomaForceLocal(String localpart, boolean on) {
        if (!domainLockEnabled) {
            return Mono.just(HomeserverOutcome.stubbed());
        }
        Map<String, Object> intended = Map.of("nick", localpart, "force_local", on);
        log.warn("[akkoma] force-local for '{}' is STUBBED — the generator ForceLocalForUsersPolicy "
                + "MRF image/verb is not wired yet; the role is DEGRADED (BFF/allowlist only) until "
                + "the MRF + egress land. wire the real call in doAkkomaForceLocal() (intended={})",
                localpart, intended);
        return Mono.just(HomeserverOutcome.stubbed());
    }

    /**
     * The tuwunel federation-lock seam. STUBBED by default. SHIPS DARK: gated on
     * {@code domainLockEnabled} (default false). tuwunel cannot self-enforce per-user
     * federation, so the egress NetworkPolicy is authoritative; even when enabled this
     * stays STUBBED until the per-instance isolation toggle + the at-lock room-hygiene
     * severance (force-leave rooms with remote servers) are wired. Never hard-fail.
     * The intended path is the admin-room command over the tuwunel-proxy mTLS sidecar,
     * roughly:
     * <pre>{@code
     *   // per-instance isolation mode (no per-user verb exists) + room severance
     *   String cmd = (on ? "!admin federation isolate @" : "!admin federation release @")
     *              + localpart + ":" + serverName;
     *   return tuwunel.post().uri(adminRoomSendPath)
     *       .header("Authorization", "Bearer " + adminToken)
     *       .bodyValue(Map.of("msgtype", "m.text", "body", cmd))
     *       .retrieve().toBodilessEntity().thenReturn(HomeserverOutcome.ok())
     *       .onErrorResume(e -> Mono.just(HomeserverOutcome.degraded(e.getMessage())));
     * }</pre>
     */
    private Mono<HomeserverOutcome> doTuwunelFederationLock(String localpart, boolean on) {
        if (!domainLockEnabled) {
            return Mono.just(HomeserverOutcome.stubbed());
        }
        Map<String, Object> intended = Map.of("localpart", localpart, "isolate", on);
        log.warn("[tuwunel] federation-lock for '{}' is STUBBED — tuwunel has no per-user federation "
                + "control; the egress NetworkPolicy is the authoritative Matrix backstop and is not "
                + "wired yet, so the role is DEGRADED until egress lands. wire the per-instance "
                + "isolation + room severance in doTuwunelFederationLock() (intended={})",
                localpart, intended);
        return Mono.just(HomeserverOutcome.stubbed());
    }
}
