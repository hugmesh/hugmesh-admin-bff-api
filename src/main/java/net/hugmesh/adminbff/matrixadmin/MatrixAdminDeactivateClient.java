package net.hugmesh.adminbff.matrixadmin;

import java.time.Duration;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicReference;
import java.util.regex.Pattern;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.web.reactive.function.client.ClientResponse;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.reactive.function.client.WebClientResponseException;
import reactor.core.publisher.Mono;

/**
 * The ONE-WAY tuwunel account deactivate — {@code !admin users deactivate <mxid>} posted
 * into the homeserver admin room. Operator decision 83b (2026-09-23, answer B): this
 * irreversible server-admin verb lives in admin-bff, reachable ONLY from the two-call
 * propose/confirm flow in {@link MatrixDeactivateService} (decision 83a = C).
 *
 * <h3>Why this is NOT {@code HomeserverAdminClient.deactivateMatrix}</h3>
 * <p>{@code HomeserverAdminClient.deactivateMatrix} is the SUSPENSION seam: the
 * access_suspension reconciler ({@code MatrixAccessSyncAction.suspendHomeserver}) calls it
 * for every active ROLE_MATRIX suspension — moderator bans included (mod-bff's
 * {@code POST /bff/mod/ban} writes that same suspension) — and expects every one of them to
 * be undone later by {@code activateMatrix}. tuwunel has no {@code activate} verb, so wiring
 * this class into that seam would make EVERY Matrix suspension permanent. The separation is
 * load-bearing and pinned by {@code MatrixSuspensionNeverDeactivatesTest}: nothing outside this
 * package may reference it.
 *
 * <h3>Transport (ported from hugmesh-mod-bff-api {@code MatrixAdminClient})</h3>
 * <p>tuwunel is Conduit-family: it has NO Synapse-style {@code /_synapse/admin} REST API.
 * Server-admin verbs are {@code !admin ...} text commands posted as {@code m.room.message}
 * events into the admin room ({@code admin_room_default}), which an in-process bot executes.
 * With {@code matrix-admin.enabled=true} and an admin bearer present
 * ({@code matrix-admin.admin-token}, Vault {@code hugmesh/tuwunel-admin} property
 * {@code token} via the ESO ExternalSecret {@code tuwunel-admin} — placeholder only, never
 * inline):
 * <ol>
 *   <li>resolve the admin-room alias to a room id once per process
 *       ({@link #DIRECTORY_PATH}, cached; dropped on ANY failure so a recreated room
 *       re-resolves);</li>
 *   <li>PUT the command as an {@code m.text} message with a fresh transaction id
 *       ({@link #SEND_PATH});</li>
 *   <li>return {@code posted:<event_id>} — NEVER an "ok": the 200 only acknowledges that the
 *       command message was accepted, not that the bot applied it.</li>
 * </ol>
 * Dark by default ({@code enabled=false} returns {@link MatrixAdminOutcome#STUBBED} with no
 * HTTP). It never throws: every failure resolves to {@code degraded:<reason>}.
 */
public class MatrixAdminDeactivateClient {

    private static final Logger log = LoggerFactory.getLogger(MatrixAdminDeactivateClient.class);

    /** Alias -> room id lookup (client-server spec; the alias is percent-encoded by WebClient). */
    static final String DIRECTORY_PATH = "/_matrix/client/v3/directory/room/{alias}";
    /** Spec send path — PUT with a per-message txnId. */
    static final String SEND_PATH = "/_matrix/client/v3/rooms/{roomId}/send/m.room.message/{txnId}";
    /** The confirmed tuwunel verb (UserCommand::Deactivate); takes a full MXID. */
    static final String DEACTIVATE_COMMAND = "!admin users deactivate ";

    /**
     * MXID grammar guard. The command is a single TEXT line the admin bot splits into
     * clap-style arguments, so whitespace or a newline inside the target would inject extra
     * arguments (e.g. {@code --no-leave-rooms}) or a second command line. Only a plain
     * {@code @localpart:server[:port]} is ever interpolated.
     */
    private static final Pattern MXID = Pattern.compile("^@[A-Za-z0-9._=/+-]+:[A-Za-z0-9.-]+(?::\\d{1,5})?$");
    private static final ParameterizedTypeReference<Map<String, Object>> JSON = new ParameterizedTypeReference<>() { };

    private final WebClient http;
    private final boolean enabled;
    private final String adminToken;
    private final String serverName;
    private final String adminRoomAlias;
    private final Duration timeout;
    /** Resolved admin-room id, cached per process; cleared on any failure. */
    private final AtomicReference<String> adminRoomId = new AtomicReference<>();

    public MatrixAdminDeactivateClient(WebClient webClient, boolean enabled, String adminToken,
                                       String serverName, String adminRoomAlias, Duration timeout) {
        this.http = webClient;
        this.enabled = enabled;
        this.adminToken = adminToken == null ? "" : adminToken.trim();
        this.serverName = serverName == null ? "" : serverName.trim();
        this.adminRoomAlias = adminRoomAlias == null ? "" : adminRoomAlias.trim();
        this.timeout = timeout == null ? Duration.ofSeconds(10) : timeout;
    }

    /** Whether the transport is armed ({@code matrix-admin.enabled}). */
    public boolean enabled() {
        return enabled;
    }

    /**
     * Post {@code !admin users deactivate <mxid>} into the admin room. ONE-WAY: tuwunel has no
     * re-activate verb. Callers MUST have passed the propose/confirm gate first — this class
     * does no authorization of its own.
     */
    public Mono<MatrixAdminOutcome> deactivate(String target) {
        if (!enabled) {
            log.info("[matrix-admin] deactivate for '{}' STUBBED (matrix-admin.enabled=false) — no HTTP", target);
            return Mono.just(MatrixAdminOutcome.STUBBED);
        }
        if (adminToken.isBlank()) {
            log.warn("[matrix-admin] deactivate for '{}' skipped — matrix-admin.admin-token is blank "
                    + "(expected from Vault hugmesh/tuwunel-admin via ESO secret tuwunel-admin)", target);
            return Mono.just(MatrixAdminOutcome.degraded("no-admin-token"));
        }
        String mxid = mxid(target);
        if (mxid == null) {
            log.warn("[matrix-admin] deactivate target '{}' is not a plain MXID — refusing to interpolate "
                    + "it into an admin-room command (degraded:bad-target)", target);
            return Mono.just(MatrixAdminOutcome.degraded("bad-target"));
        }
        String command = DEACTIVATE_COMMAND + mxid;
        return resolveAdminRoom()
                .flatMap(roomId -> sendCommand(roomId, command))
                .switchIfEmpty(Mono.fromSupplier(() -> noAdminRoom(mxid)))
                .timeout(timeout)
                .onErrorResume(e -> degrade(e, mxid));
    }

    /** Alias -> room id, cached per process; empty when the directory reply carries no room id. */
    private Mono<String> resolveAdminRoom() {
        String cached = adminRoomId.get();
        if (cached != null) {
            return Mono.just(cached);
        }
        return http.get()
                .uri(DIRECTORY_PATH, adminRoomAlias)
                .header("Authorization", "Bearer " + adminToken)
                .retrieve()
                .onStatus(s -> !s.is2xxSuccessful(), ClientResponse::createException)
                .bodyToMono(JSON)
                .flatMap(MatrixAdminDeactivateClient::roomIdOf)
                .doOnNext(adminRoomId::set);
    }

    private static Mono<String> roomIdOf(Map<String, Object> body) {
        Object id = body.get("room_id");
        if (id instanceof String s && s.startsWith("!")) {
            return Mono.just(s);
        }
        return Mono.empty();
    }

    /** PUT the command as an m.text message with a fresh txnId; map the event id to posted. */
    private Mono<MatrixAdminOutcome> sendCommand(String roomId, String command) {
        String txnId = "adminbff-" + UUID.randomUUID();
        return http.put()
                .uri(SEND_PATH, roomId, txnId)
                .header("Authorization", "Bearer " + adminToken)
                .bodyValue(Map.of("msgtype", "m.text", "body", command))
                .retrieve()
                .onStatus(s -> !s.is2xxSuccessful(), ClientResponse::createException)
                .bodyToMono(JSON)
                .defaultIfEmpty(Map.of())
                .map(body -> postedOutcome(body, command));
    }

    private static MatrixAdminOutcome postedOutcome(Map<String, Object> body, String command) {
        Object id = body.get("event_id");
        if (id instanceof String s && !s.isBlank()) {
            log.info("[matrix-admin] admin-room command posted ({}): '{}' — effect is asynchronous and NOT "
                    + "yet correlated", s, command);
            return MatrixAdminOutcome.posted(s);
        }
        log.warn("[matrix-admin] admin-room send returned 2xx without an event_id for '{}' — degrading", command);
        return MatrixAdminOutcome.degraded("no-event-id");
    }

    private MatrixAdminOutcome noAdminRoom(String mxid) {
        log.warn("[matrix-admin] admin room alias '{}' did not resolve to a room id — cannot post the "
                + "deactivate for {} (degraded:no-admin-room)", adminRoomAlias, mxid);
        return MatrixAdminOutcome.degraded("no-admin-room");
    }

    /** Degrade on ANY failure — never throw — and drop the cached room id so we re-resolve. */
    private Mono<MatrixAdminOutcome> degrade(Throwable e, String mxid) {
        adminRoomId.set(null);
        String reason;
        if (e instanceof WebClientResponseException w) {
            reason = "http-" + w.getStatusCode().value();
        } else if (e instanceof TimeoutException) {
            reason = "timeout";
        } else {
            reason = "transport-" + e.getClass().getSimpleName();
        }
        log.warn("[matrix-admin] admin-room call for {} failed ({}), degrading", mxid, reason);
        return Mono.just(MatrixAdminOutcome.degraded(reason));
    }

    /**
     * Normalise an admin-supplied target to a full MXID, or {@code null} when it is not one:
     * {@code @user:server} passes through; {@code user:server} gains the {@code @}; a bare
     * {@code user} is qualified to {@code @user:<server-name>}. Anything that still fails the
     * {@link #MXID} grammar (whitespace, newlines, shell characters) is rejected so it can
     * never widen the admin-room command.
     */
    public String mxid(String target) {
        String s = target == null ? "" : target.trim();
        if (s.isEmpty()) {
            return null;
        }
        if (!s.startsWith("@")) {
            s = "@" + s;
        }
        if (s.indexOf(':') < 0) {
            if (serverName.isBlank()) {
                return null;
            }
            s = s + ":" + serverName;
        }
        return MXID.matcher(s).matches() ? s : null;
    }
}
