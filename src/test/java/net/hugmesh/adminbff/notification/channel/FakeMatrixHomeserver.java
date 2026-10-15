package net.hugmesh.adminbff.notification.channel;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * A real HTTP server (JDK {@code HttpServer}, loopback, ephemeral port) that plays a Matrix
 * homeserver for the contract tests: just the client-server endpoints the {@code @system}
 * DM transport uses. Part of its semantics was MEASURED against a tuwunel v1.7.0 container on
 * 2026-10-14 (the list below says which, including the surprising ones); the forced 403/404/429/5xx
 * replies were not measured:
 * <ul>
 *   <li>{@code createRoom} inviting an UNKNOWN local user still answers 200 with a room id,
 *       so only {@code GET /profile} (404 {@code M_NOT_FOUND}) reveals the account does not
 *       exist;</li>
 *   <li>the same txn id sent twice into a room yields the SAME event id and ONE event;</li>
 *   <li>{@code m.direct} account data is 404 {@code M_NOT_FOUND} until first written;</li>
 *   <li>an unknown access token is 401 {@code M_UNKNOWN_TOKEN} (only the {@code whoami} reply
 *       is checked by a test; the other endpoints answer it the same way in this fake, which
 *       was not measured on the real server).</li>
 * </ul>
 * Because it is a real server the client under test uses its real {@code WebClient} and
 * socket path, not a mocked exchange function. It records every request and offers fault
 * injection (forced status per path suffix, a committed-but-unanswered send).
 */
final class FakeMatrixHomeserver implements AutoCloseable {

    static final String SERVER = "probe.test";
    static final String SYSTEM_TOKEN = "syt_system_token";
    static final String SYSTEM_ID = "@system:" + SERVER;

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final String V3 = "/_matrix/client/v3/";

    /** A recorded request: method, DECODED path, bearer token and parsed JSON body. */
    record Seen(String method, String path, String bearer, JsonNode body) { }

    /** A posted event. */
    record Event(String room, String txn, String msgtype, String body, String eventId) { }

    final List<Seen> requests = Collections.synchronizedList(new ArrayList<>());
    final List<Event> events = Collections.synchronizedList(new ArrayList<>());
    final Map<String, JsonNode> accountData = new HashMap<>();
    final Set<String> users = new HashSet<>(Set.of(SYSTEM_ID, "@alice:" + SERVER, "@bob:" + SERVER));
    /** room id -> the user it was created for. */
    final Map<String, String> roomInvitee = new LinkedHashMap<>();
    /** Rooms the system user can no longer post into (left / forgotten). */
    final Set<String> deadRooms = new HashSet<>();
    /** Status a send into a dead room answers with (403 by default, 404 in one test; neither measured on a real homeserver). */
    volatile int deadRoomStatus = 403;
    /** "METHOD path-suffix" -> status to answer with instead of handling the request. */
    final Map<String, Integer> forcedStatus = new HashMap<>();
    /** When true the next send commits the event and then drops the connection unanswered. */
    volatile boolean dropNextSendReply;

    private final Map<String, String> txnToEvent = new HashMap<>();
    private final AtomicInteger rooms = new AtomicInteger();
    private final AtomicInteger eventSeq = new AtomicInteger();
    private final HttpServer server;

    FakeMatrixHomeserver() throws IOException {
        server = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
        server.createContext("/", this::handle);
        server.start();
    }

    String baseUrl() {
        return "http://127.0.0.1:" + server.getAddress().getPort();
    }

    long count(String method, String pathContains) {
        synchronized (requests) {
            return requests.stream()
                    .filter(r -> r.method().equals(method) && r.path().contains(pathContains)).count();
        }
    }

    @Override
    public void close() {
        server.stop(0);
    }

    // The handler runs on the server's single dispatcher thread, so the fake's own maps
    // need no further locking; tests read them after the client call has returned.
    private void handle(HttpExchange ex) throws IOException {
        String m = ex.getRequestMethod();
        String path = URLDecoder.decode(ex.getRequestURI().getRawPath().replace("+", "%2B"), StandardCharsets.UTF_8);
        String auth = ex.getRequestHeaders().getFirst("Authorization");
        String bearer = auth != null && auth.startsWith("Bearer ") ? auth.substring(7) : null;
        String raw = new String(ex.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
        JsonNode body = raw.isBlank() ? MAPPER.createObjectNode() : MAPPER.readTree(raw);
        requests.add(new Seen(m, path, bearer, body));

        for (Map.Entry<String, Integer> f : forcedStatus.entrySet()) {
            String[] mp = f.getKey().split(" ", 2);
            if (mp[0].equals(m) && path.endsWith(mp[1])) {
                reply(ex, f.getValue(), "{\"errcode\":\"M_LIMIT_EXCEEDED\",\"error\":\"forced\"}");
                return;
            }
        }
        if (!SYSTEM_TOKEN.equals(bearer)) {
            reply(ex, 401, "{\"errcode\":\"M_UNKNOWN_TOKEN\",\"error\":\"M_UNKNOWN_TOKEN: Unknown access token.\"}");
            return;
        }
        String direct = V3 + "user/" + SYSTEM_ID + "/account_data/m.direct";
        if (m.equals("GET") && path.equals(V3 + "account/whoami")) {
            reply(ex, 200, "{\"user_id\":\"" + SYSTEM_ID + "\",\"device_id\":\"DEV\"}");
        } else if (m.equals("GET") && path.startsWith(V3 + "profile/")) {
            String who = path.substring((V3 + "profile/").length());
            if (users.contains(who)) {
                reply(ex, 200, "{\"displayname\":\"" + who + "\"}");
            } else {
                reply(ex, 404, "{\"errcode\":\"M_NOT_FOUND\",\"error\":\"M_NOT_FOUND: Profile was not found.\"}");
            }
        } else if (m.equals("GET") && path.equals(direct)) {
            JsonNode d = accountData.get("m.direct");
            if (d == null) {
                reply(ex, 404, "{\"errcode\":\"M_NOT_FOUND\",\"error\":\"M_NOT_FOUND: Data not found.\"}");
            } else {
                reply(ex, 200, d.toString());
            }
        } else if (m.equals("PUT") && path.equals(direct)) {
            accountData.put("m.direct", body);
            reply(ex, 200, "{}");
        } else if (m.equals("POST") && path.equals(V3 + "createRoom")) {
            String room = "!room" + rooms.incrementAndGet() + ":" + SERVER;
            roomInvitee.put(room, body.path("invite").path(0).asText());
            reply(ex, 200, "{\"room_id\":\"" + room + "\"}");
        } else if (m.equals("PUT") && path.startsWith(V3 + "rooms/") && path.contains("/send/m.room.message/")) {
            send(ex, path, body);
        } else {
            reply(ex, 404, "{\"errcode\":\"M_UNRECOGNIZED\",\"error\":\"" + m + " " + path + "\"}");
        }
    }

    private void send(HttpExchange ex, String path, JsonNode body) throws IOException {
        String rest = path.substring((V3 + "rooms/").length());
        String room = rest.substring(0, rest.indexOf("/send/"));
        String txn = rest.substring(rest.lastIndexOf('/') + 1);
        if (!roomInvitee.containsKey(room) || deadRooms.contains(room)) {
            reply(ex, deadRoomStatus, "{\"errcode\":\"M_FORBIDDEN\",\"error\":\"not in room\"}");
            return;
        }
        String key = room + "|" + txn;
        String id = txnToEvent.get(key);
        if (id == null) {
            id = "$ev" + eventSeq.incrementAndGet();
            txnToEvent.put(key, id);
            events.add(new Event(room, txn, body.path("msgtype").asText(), body.path("body").asText(), id));
        }
        if (dropNextSendReply) {
            dropNextSendReply = false;
            ex.close(); // committed, but the reply is lost
            return;
        }
        reply(ex, 200, "{\"event_id\":\"" + id + "\"}");
    }

    private static void reply(HttpExchange ex, int status, String json) throws IOException {
        byte[] b = json.getBytes(StandardCharsets.UTF_8);
        ex.getResponseHeaders().add("Content-Type", "application/json");
        ex.sendResponseHeaders(status, b.length);
        ex.getResponseBody().write(b);
        ex.close();
    }

    /** All DM rooms created, in order. */
    List<String> createdRooms() {
        return new ArrayList<>(roomInvitee.keySet());
    }
}
