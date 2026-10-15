package net.hugmesh.adminbff.notification.channel;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;
import net.hugmesh.adminbff.notification.SystemChannelTokens;

import java.time.Duration;
import java.util.Iterator;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicReference;
import java.util.regex.Pattern;

/**
 * The REAL Matrix {@code @system} direct-message transport (Notifications external
 * channels, Matrix leg). It speaks the standard Matrix client-server API to the tuwunel
 * homeserver as the {@code @system} account, using that account's own access token. It
 * does NOT use the tuwunel admin-room command transport the suspend/lock seams are stuck
 * with ({@code HomeserverAdminClient}); a DM is an ordinary client action.
 *
 * <h3>Wire sequence (profile, m.direct and txn-id behaviour measured on tuwunel v1.7.0, see the PR body; the dead-room 403/404 reply is not)</h3>
 * <ol>
 *   <li>{@code GET /_matrix/client/v3/account/whoami} — learns the {@code @system} user id,
 *       hence the homeserver name, so no server-name config can drift from the token.
 *       Cached; dropped on a 401.</li>
 *   <li>{@code GET /_matrix/client/v3/profile/{mxid}} — <b>existence probe</b>. tuwunel
 *       answers {@code createRoom} with an invite to an UNKNOWN local user with 200, so
 *       without this probe a user with no Matrix account would be "delivered" into a dead
 *       room and recorded {@code sent}. A 404 here is the terminal {@link ChannelOutcome#SKIPPED}.</li>
 *   <li>DM room: in-memory cache, else the {@code @system}'s {@code m.direct} account data,
 *       else {@code POST /_matrix/client/v3/createRoom} ({@code is_direct},
 *       {@code trusted_private_chat}) followed by a best-effort {@code m.direct} update so
 *       the room survives a restart and is not re-created per notification.</li>
 *   <li>{@code PUT /_matrix/client/v3/rooms/{room}/send/m.room.message/{txn}} with an
 *       {@code m.text} body. {@code m.text}, never {@code m.notice}: clients suppress push
 *       for notices, and an account-restriction message must reach the user.</li>
 * </ol>
 *
 * <h3>Idempotent retry</h3>
 * The transaction id is derived from the outbox row id ({@link ChannelMessage#deliveryKey()}).
 * A reply lost after the homeserver accepted the event is retried by the reconciler with
 * the SAME txn id, and the homeserver returns the original event id instead of posting a
 * second copy (verified live: same txn twice, one event in the room). With no key a random
 * txn id is used (no dedupe).
 *
 * <h3>Never throws</h3>
 * Every failure (transport error, 4xx/5xx, malformed JSON, rate limit, timeout) resolves to
 * {@link ChannelOutcome#FAILED} so the reconciler retries next tick. Only a blank/invalid
 * recipient or a recipient with no Matrix account is the terminal {@link ChannelOutcome#SKIPPED}.
 * The access token is never logged.
 *
 * <h3>Known limits</h3>
 * In the gone-room self-heal the {@code m.direct} re-read that precedes the best-effort
 * update treats any non-2xx reply (a 5xx as well as the 404 of a first write) as an empty
 * map, so that update can replace the stored {@code m.direct} with a single entry. No test
 * covers it.
 *
 * <p>Ships dark: this bean only exists when {@code notify.matrix.dm.wired=true}
 * (default false); the channel itself is separately gated by {@code notify.matrix.enabled}.
 */
@SuppressFBWarnings(value = "EI_EXPOSE_REP2",
        justification = "Spring constructor injection: the container owns these singleton collaborators and they are never mutated by this class after construction; a defensive copy of a bean is meaningless (not caller-owned mutable data).")
public class MatrixSystemDmClient {

    private static final Logger log = LoggerFactory.getLogger(MatrixSystemDmClient.class);
    private static final ObjectMapper MAPPER = new ObjectMapper();

    /** The Matrix grammar for a user-id localpart (spec: historical user ids). Anything
     *  else cannot be a tuwunel account, so it is a terminal SKIP, never a request. */
    private static final Pattern LOCALPART = Pattern.compile("[a-z0-9._=+-]+");
    private static final Pattern TXN_UNSAFE = Pattern.compile("[^A-Za-z0-9_-]");
    private static final int MAX_LOCALPART = 255;

    private final WebClient http;
    private final SystemChannelTokens tokens;
    private final Duration timeout;

    /** {@code @system:server} — from whoami; null until first resolved. */
    private final AtomicReference<String> selfId = new AtomicReference<>();
    /** recipient mxid -> DM room id. A hint only: a 403/404 on send invalidates it. */
    private final ConcurrentHashMap<String, String> rooms = new ConcurrentHashMap<>();

    public MatrixSystemDmClient(WebClient http, SystemChannelTokens tokens, Duration timeout) {
        this.http = http;
        this.tokens = tokens;
        this.timeout = timeout;
    }

    /** One HTTP exchange: the status and the parsed JSON body ({@code null} when empty or
     *  not JSON). A non-2xx status is DATA here, not an error. */
    private record Reply(int status, JsonNode body) {
        boolean ok() {
            return status >= 200 && status < 300;
        }
    }

    /**
     * Deliver {@code text} as a DM from {@code @system} to the local user {@code localpart}.
     *
     * @param deliveryKey stable id of the outbox row (txn-id source); may be null
     */
    public Mono<ChannelOutcome> sendDirectMessage(String localpart, String text, String deliveryKey) {
        String lp = localpart == null ? "" : localpart.trim();
        if (lp.isEmpty() || lp.length() > MAX_LOCALPART || !LOCALPART.matcher(lp).matches()) {
            return Mono.just(ChannelOutcome.SKIPPED);
        }
        String token = tokens.matrix().orElse(null);
        if (token == null) {
            // available() is false without a token, so this is unreachable via the
            // reconciler; fail closed (retry) rather than pretend.
            return Mono.just(ChannelOutcome.FAILED);
        }
        String txn = deliveryKey == null || deliveryKey.isBlank()
                ? UUID.randomUUID().toString()
                : "hm-" + TXN_UNSAFE.matcher(deliveryKey).replaceAll("_");
        return self(token)
                .flatMap(me -> deliver(token, me, "@" + lp + ":" + serverOf(me), lp, text, txn))
                .onErrorResume(e -> {
                    log.warn("[notify-matrix] DM to '{}' failed (retry next tick): {}", lp, e.toString());
                    return Mono.just(ChannelOutcome.FAILED);
                })
                .defaultIfEmpty(ChannelOutcome.FAILED);
    }

    private Mono<ChannelOutcome> deliver(String token, String me, String mxid, String lp,
                                         String text, String txn) {
        return call(token, HttpMethod.GET, "/_matrix/client/v3/profile/{mxid}", null, mxid)
                .flatMap(profile -> afterProfile(profile, token, me, mxid, lp, text, txn));
    }

    private Mono<ChannelOutcome> afterProfile(Reply profile, String token, String me, String mxid,
                                              String lp, String text, String txn) {
        if (profile.status() == 404) {
            log.debug("[notify-matrix] {} has no Matrix account; SKIPPED", mxid);
            return Mono.just(ChannelOutcome.SKIPPED);
        }
        if (!profile.ok()) {
            return failed("profile probe", lp, profile);
        }
        return roomFor(token, me, mxid)
                .flatMap(room -> sendInto(token, room, text, txn)
                        .flatMap(r -> retryInFreshRoomIfGone(token, me, mxid, room, text, txn, r)))
                .map(r -> r.ok() ? ChannelOutcome.SENT : failedOutcome("send", lp, r));
    }

    /** A cached/stored room we have left or that no longer exists answers 403/404 on send:
     *  forget it, make a fresh DM, and send once more. Any other result passes through. */
    private Mono<Reply> retryInFreshRoomIfGone(String token, String me, String mxid, String room,
                                               String text, String txn, Reply first) {
        if (first.status() != 403 && first.status() != 404) {
            return Mono.just(first);
        }
        rooms.remove(mxid, room);
        return createRoom(token, me, mxid, null)
                .flatMap(fresh -> sendInto(token, fresh, text, txn));
    }

    private Mono<Reply> sendInto(String token, String room, String text, String txn) {
        ObjectNode body = MAPPER.createObjectNode();
        body.put("msgtype", "m.text");
        body.put("body", text == null ? "" : text);
        return call(token, HttpMethod.PUT,
                "/_matrix/client/v3/rooms/{room}/send/m.room.message/{txn}", body, room, txn);
    }

    // ── room resolution ───────────────────────────────────────────────────────

    private Mono<String> roomFor(String token, String me, String mxid) {
        String cached = rooms.get(mxid);
        if (cached != null) {
            return Mono.just(cached);
        }
        return call(token, HttpMethod.GET,
                "/_matrix/client/v3/user/{me}/account_data/m.direct", null, me)
                .flatMap(r -> afterDirectRead(r, token, me, mxid));
    }

    private Mono<String> afterDirectRead(Reply r, String token, String me, String mxid) {
        if (r.status() == 404) {
            return createRoom(token, me, mxid, MAPPER.createObjectNode());
        }
        if (!r.ok()) {
            return Mono.<String>error(new IllegalStateException(
                    "m.direct read HTTP " + r.status()));
        }
        JsonNode direct = r.body() == null ? MAPPER.createObjectNode() : r.body();
        String known = lastRoom(direct.get(mxid));
        if (known != null) {
            rooms.put(mxid, known);
            return Mono.just(known);
        }
        return createRoom(token, me, mxid, direct);
    }

    /**
     * Create the DM, remember it, and (best effort) record it in {@code m.direct}.
     *
     * @param direct the {@code m.direct} content already read, or null to re-read it
     */
    private Mono<String> createRoom(String token, String me, String mxid, JsonNode direct) {
        ObjectNode req = MAPPER.createObjectNode();
        req.put("is_direct", true);
        req.put("preset", "trusted_private_chat");
        req.putArray("invite").add(mxid);
        return call(token, HttpMethod.POST, "/_matrix/client/v3/createRoom", req)
                .flatMap(r -> afterCreate(r, token, me, mxid, direct));
    }

    private Mono<String> afterCreate(Reply r, String token, String me, String mxid, JsonNode direct) {
        String room = r.ok() && r.body() != null && r.body().hasNonNull("room_id")
                ? r.body().get("room_id").asText() : null;
        if (room == null) {
            return Mono.<String>error(new IllegalStateException(
                    "createRoom HTTP " + r.status()));
        }
        // Cache FIRST: if the m.direct write below fails we must still reuse
        // this room on the next send instead of creating a second one.
        rooms.put(mxid, room);
        Mono<JsonNode> current = direct != null ? Mono.just(direct)
                : call(token, HttpMethod.GET,
                        "/_matrix/client/v3/user/{me}/account_data/m.direct", null, me)
                        .map(d -> d.ok() && d.body() != null ? d.body() : MAPPER.createObjectNode());
        return current
                .flatMap(cur -> call(token, HttpMethod.PUT,
                        "/_matrix/client/v3/user/{me}/account_data/m.direct",
                        withRoom(cur, mxid, room), me))
                .doOnNext(w -> {
                    if (!w.ok()) {
                        log.warn("[notify-matrix] m.direct update HTTP {} (room still cached)", w.status());
                    }
                })
                .onErrorResume(e -> {
                    log.warn("[notify-matrix] m.direct update failed (room still cached): {}", e.toString());
                    return Mono.empty();
                })
                .thenReturn(room);
    }

    /** {@code direct} plus {@code room} appended under {@code mxid}; the input is not mutated. */
    private static ObjectNode withRoom(JsonNode direct, String mxid, String room) {
        ObjectNode out = direct.isObject() ? ((ObjectNode) direct).deepCopy() : MAPPER.createObjectNode();
        ArrayNode list = out.has(mxid) && out.get(mxid).isArray()
                ? (ArrayNode) out.get(mxid) : out.putArray(mxid);
        list.add(room);
        return out;
    }

    /** The most recent room id in an {@code m.direct} entry (appended last), or null. */
    private static String lastRoom(JsonNode entry) {
        if (entry == null || !entry.isArray() || entry.isEmpty()) {
            return null;
        }
        String last = null;
        for (Iterator<JsonNode> it = entry.elements(); it.hasNext();) {
            JsonNode n = it.next();
            if (n.isTextual() && !n.asText().isBlank()) {
                last = n.asText();
            }
        }
        return last;
    }

    // ── identity ──────────────────────────────────────────────────────────────

    private Mono<String> self(String token) {
        String known = selfId.get();
        if (known != null) {
            return Mono.just(known);
        }
        return call(token, HttpMethod.GET, "/_matrix/client/v3/account/whoami", null)
                .flatMap(r -> {
                    String id = r.ok() && r.body() != null && r.body().hasNonNull("user_id")
                            ? r.body().get("user_id").asText() : null;
                    if (id == null || !id.startsWith("@") || id.indexOf(':') < 2) {
                        return Mono.<String>error(new IllegalStateException("whoami HTTP " + r.status()));
                    }
                    selfId.set(id);
                    return Mono.just(id);
                });
    }

    /** {@code @system:server.name:8448} -> {@code server.name:8448}. */
    static String serverOf(String mxid) {
        return mxid.substring(mxid.indexOf(':') + 1);
    }

    // ── transport ─────────────────────────────────────────────────────────────

    private Mono<Reply> call(String token, HttpMethod method, String uri, JsonNode body, Object... vars) {
        WebClient.RequestBodySpec spec = http.method(method).uri(uri, vars)
                .headers(h -> h.setBearerAuth(token))
                .accept(MediaType.APPLICATION_JSON);
        // The body is serialised HERE and sent as a String. Spring Boot 4's WebClient codecs
        // are Jackson 3; a Jackson 2 ObjectNode handed to bodyValue is not encoded as the
        // JSON tree (it went out empty and createRoom lost is_direct/invite).
        WebClient.RequestHeadersSpec<?> req = body == null ? spec
                : spec.contentType(MediaType.APPLICATION_JSON).bodyValue(body.toString());
        return req.exchangeToMono(resp -> resp.bodyToMono(String.class)
                        .defaultIfEmpty("")
                        .map(raw -> new Reply(resp.statusCode().value(), parse(raw))))
                .timeout(timeout)
                .doOnNext(r -> {
                    if (r.status() == 401) {
                        // The token was rotated or revoked: forget the cached identity.
                        selfId.set(null);
                    }
                });
    }

    private static JsonNode parse(String raw) {
        if (raw == null || raw.isBlank()) {
            return null;
        }
        try {
            return MAPPER.readTree(raw);
        } catch (Exception e) {
            return null;
        }
    }

    private static Mono<ChannelOutcome> failed(String what, String lp, Reply r) {
        return Mono.just(failedOutcome(what, lp, r));
    }

    private static ChannelOutcome failedOutcome(String what, String lp, Reply r) {
        String errcode = r.body() != null && r.body().hasNonNull("errcode")
                ? r.body().get("errcode").asText() : "-";
        log.warn("[notify-matrix] {} for '{}' HTTP {} {} (retry next tick)", what, lp, r.status(), errcode);
        return ChannelOutcome.FAILED;
    }

    /** Test seam: the rooms this client has cached (recipient mxid -> room id). */
    Map<String, String> cachedRooms() {
        return Map.copyOf(rooms);
    }
}
