package net.hugmesh.adminbff.notification.channel;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.web.reactive.function.client.WebClient;
import net.hugmesh.adminbff.notification.SystemChannelTokens;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Contract tests for the phpBB {@code @system} private-message transport against an in-JVM
 * fake forum-bff. The fake encodes the PROPOSED contract in {@link ForumSystemPmClient}'s
 * javadoc: no real forum-bff or phpBB serves it, so nothing here was measured on one.
 */
class ForumSystemPmClientTest {

    private static final String TOKEN = "forum-system-token";
    private static final ObjectMapper MAPPER = new ObjectMapper();

    record Seen(String method, String path, String bearer, String idemKey, JsonNode body) { }

    private HttpServer server;
    private final List<Seen> requests = Collections.synchronizedList(new ArrayList<>());
    private final Map<String, String> idemReplay = new HashMap<>();
    private final List<JsonNode> messages = Collections.synchronizedList(new ArrayList<>());
    private final Set<String> users = Set.of("hugmesh/alice", "hugmesh/bob");
    private volatile int forceStatus = 0;
    private volatile String forceBody = "{\"error\":\"forced\"}";
    private volatile boolean routeAbsent = false;
    private volatile boolean dropNextReply = false;

    @BeforeEach
    void up() throws IOException {
        server = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
        server.createContext("/", this::handle);
        server.start();
    }

    @AfterEach
    void down() {
        server.stop(0);
    }

    private void handle(HttpExchange ex) throws IOException {
        String auth = ex.getRequestHeaders().getFirst("Authorization");
        String bearer = auth != null && auth.startsWith("Bearer ") ? auth.substring(7) : null;
        String raw = new String(ex.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
        JsonNode body = raw.isBlank() ? MAPPER.createObjectNode() : MAPPER.readTree(raw);
        String path = ex.getRequestURI().getPath();
        String key = ex.getRequestHeaders().getFirst("Idempotency-Key");
        requests.add(new Seen(ex.getRequestMethod(), path, bearer, key, body));
        if (routeAbsent || !ex.getRequestMethod().equals("POST") || !path.equals(ForumSystemPmClient.PATH)) {
            reply(ex, 404, "{\"error\":\"Not Found\"}");
        } else if (!TOKEN.equals(bearer)) {
            reply(ex, 401, "{\"error\":\"bad token\"}");
        } else if (forceStatus != 0) {
            reply(ex, forceStatus, forceBody);
        } else if (!users.contains(body.path("recipient").asText())) {
            reply(ex, 404, "{\"code\":\"unknown_recipient\"}");
        } else {
            String replay = key == null ? null : idemReplay.get(key);
            if (replay == null) {
                messages.add(body);
                replay = "{\"id\":" + messages.size() + "}";
                if (key != null) {
                    idemReplay.put(key, replay);
                }
            }
            if (dropNextReply) {
                dropNextReply = false;
                ex.close();
                return;
            }
            reply(ex, 200, replay);
        }
    }

    private static void reply(HttpExchange ex, int status, String json) throws IOException {
        byte[] b = json.getBytes(StandardCharsets.UTF_8);
        ex.getResponseHeaders().add("Content-Type", "application/json");
        ex.sendResponseHeaders(status, b.length);
        ex.getResponseBody().write(b);
        ex.close();
    }

    private ForumSystemPmClient client(String token) {
        return new ForumSystemPmClient(
                WebClient.builder().baseUrl("http://127.0.0.1:" + server.getAddress().getPort()).build(),
                new SystemChannelTokens("", "", "", token), Duration.ofSeconds(5));
    }

    private ForumSystemPmClient client() {
        return client(TOKEN);
    }

    @Test
    void happyPath_postsOneMessageWithTheBearerSubjectTextAndIdempotencyKey() {
        ChannelOutcome out = client().sendPrivateMessage("hugmesh/alice", "Title", "Body", "row-1").block();

        assertThat(out).isEqualTo(ChannelOutcome.SENT);
        assertThat(requests).extracting(r -> r.method() + " " + r.path())
                .containsExactly("POST /bff/forum/system/private-messages");
        assertThat(requests.get(0).bearer()).isEqualTo(TOKEN);
        assertThat(requests.get(0).idemKey()).isEqualTo("hm-row-1");
        assertThat(messages.get(0).get("recipient").asText()).isEqualTo("hugmesh/alice");
        assertThat(messages.get(0).get("subject").asText()).isEqualTo("Title");
        assertThat(messages.get(0).get("text").asText()).isEqualTo("Body");
    }

    @Test
    void unknownRecipient_isSkipped_andNothingIsPosted() {
        assertThat(client().sendPrivateMessage("hugmesh/ghost", "T", "B", "r").block())
                .isEqualTo(ChannelOutcome.SKIPPED);
        assertThat(messages).isEmpty();
    }

    @Test
    void absentRoute_a404WithoutTheRecipientCode_isFailedRetry_notASkip() {
        routeAbsent = true;
        assertThat(client().sendPrivateMessage("hugmesh/alice", "T", "B", "r").block())
                .isEqualTo(ChannelOutcome.FAILED);
        assertThat(messages).isEmpty();
    }

    @Test
    void a404CarryingADifferentCode_isFailed() {
        forceStatus = 404;
        forceBody = "{\"code\":\"forum_disabled\"}";
        assertThat(client().sendPrivateMessage("hugmesh/alice", "T", "B", "r").block())
                .isEqualTo(ChannelOutcome.FAILED);
    }

    @Test
    void blankRecipient_isSkipped_withoutAnyRequest() {
        for (String bad : new String[] {null, "", "   "}) {
            assertThat(client().sendPrivateMessage(bad, "T", "B", "r").block()).as("recipient=%s", bad)
                    .isEqualTo(ChannelOutcome.SKIPPED);
        }
        assertThat(requests).isEmpty();
    }

    @Test
    void replyLostAfterCommit_retryWithSameKey_postsExactlyOneMessage() {
        ForumSystemPmClient c = client();
        dropNextReply = true;
        assertThat(c.sendPrivateMessage("hugmesh/alice", "T", "B", "outbox-9").block())
                .isEqualTo(ChannelOutcome.FAILED);
        assertThat(messages).hasSize(1);
        assertThat(c.sendPrivateMessage("hugmesh/alice", "T", "B", "outbox-9").block())
                .isEqualTo(ChannelOutcome.SENT);
        assertThat(messages).as("same Idempotency-Key => replayed, not re-posted").hasSize(1);
    }

    @Test
    void wrongToken_isFailed_andPostsNothing() {
        assertThat(client("nope").sendPrivateMessage("hugmesh/alice", "T", "B", "r").block())
                .isEqualTo(ChannelOutcome.FAILED);
        assertThat(messages).isEmpty();
    }

    @Test
    void absentToken_isFailed_withoutAnyRequest() {
        assertThat(client("").sendPrivateMessage("hugmesh/alice", "T", "B", "r").block())
                .isEqualTo(ChannelOutcome.FAILED);
        assertThat(requests).isEmpty();
    }

    @Test
    void serverErrors_areFailed() {
        for (int status : new int[] {422, 429, 500, 503}) {
            forceStatus = status;
            assertThat(client().sendPrivateMessage("hugmesh/alice", "T", "B", "r").block())
                    .as("HTTP %d", status).isEqualTo(ChannelOutcome.FAILED);
        }
        assertThat(messages).isEmpty();
    }

    @Test
    void serverDown_isFailed() {
        ForumSystemPmClient c = client();
        server.stop(0);
        assertThat(c.sendPrivateMessage("hugmesh/alice", "T", "B", "r").block()).isEqualTo(ChannelOutcome.FAILED);
    }

    // ── through the channel adapter ──────────────────────────────────────────
    @Test
    void channel_withRealTransport_sendsAndIgnoresTheSeamWiredFlag() {
        ForumChannel ch = new ForumChannel(true, false, true, client());

        assertThat(ch.available("brandx").block()).isTrue();
        assertThat(ch.send("brandx", "hugmesh/alice",
                new ChannelMessage("account-restriction", "T", "B", "row-3")).block())
                .isEqualTo(ChannelOutcome.SENT);
        assertThat(messages.get(0).get("text").asText()).isEqualTo("B");
        assertThat(requests.get(0).idemKey()).isEqualTo("hm-row-3");
        // the channel gate and the token are still required
        assertThat(new ForumChannel(false, true, true, client()).available("d").block()).isFalse();
        assertThat(new ForumChannel(true, true, false, client()).available("d").block()).isFalse();
        // and without the real transport the unwired seam keeps it unavailable, as before
        assertThat(new ForumChannel(true, false, true).available("d").block()).isFalse();
    }
}
