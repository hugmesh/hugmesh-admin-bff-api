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
 * Contract tests for the real Akkoma {@code @system} notice transport against an in-JVM
 * Mastodon-API fake. UNLIKE the Matrix fake, this one's semantics are taken from the
 * Mastodon/Akkoma API documentation, not measured on a running Akkoma (none was available):
 * lookup 404 for an unknown account, and a repeated {@code Idempotency-Key} replaying the
 * first response. That is exactly the part to re-check live before turning the flag on.
 */
class AkkomaSystemNoticeClientTest {

    private static final String TOKEN = "akkoma-system-token";
    private static final ObjectMapper MAPPER = new ObjectMapper();

    record Seen(String method, String path, String query, String bearer, String idemKey, JsonNode body) { }

    private HttpServer server;
    private final List<Seen> requests = Collections.synchronizedList(new ArrayList<>());
    private final Map<String, String> idemReplay = new HashMap<>();
    private final List<JsonNode> statuses = Collections.synchronizedList(new ArrayList<>());
    private final Set<String> accounts = Set.of("alice", "bob");
    private volatile int forcePostStatus = 0;
    private volatile boolean dropNextPostReply = false;

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
        requests.add(new Seen(ex.getRequestMethod(), path, ex.getRequestURI().getQuery(), bearer,
                ex.getRequestHeaders().getFirst("Idempotency-Key"), body));
        if (!TOKEN.equals(bearer)) {
            reply(ex, 401, "{\"error\":\"The access token is invalid\"}");
        } else if (ex.getRequestMethod().equals("GET") && path.equals("/api/v1/accounts/lookup")) {
            String acct = ex.getRequestURI().getQuery().replace("acct=", "");
            if (accounts.contains(acct)) {
                reply(ex, 200, "{\"id\":\"1\",\"acct\":\"" + acct + "\"}");
            } else {
                reply(ex, 404, "{\"error\":\"Record not found\"}");
            }
        } else if (ex.getRequestMethod().equals("POST") && path.equals("/api/v1/statuses")) {
            if (forcePostStatus != 0) {
                reply(ex, forcePostStatus, "{\"error\":\"forced\"}");
                return;
            }
            String key = ex.getRequestHeaders().getFirst("Idempotency-Key");
            String replay = key == null ? null : idemReplay.get(key);
            if (replay == null) {
                statuses.add(body);
                replay = "{\"id\":\"" + statuses.size() + "\",\"visibility\":\"direct\"}";
                if (key != null) {
                    idemReplay.put(key, replay);
                }
            }
            if (dropNextPostReply) {
                dropNextPostReply = false;
                ex.close();
                return;
            }
            reply(ex, 200, replay);
        } else {
            reply(ex, 404, "{\"error\":\"nope\"}");
        }
    }

    private static void reply(HttpExchange ex, int status, String json) throws IOException {
        byte[] b = json.getBytes(StandardCharsets.UTF_8);
        ex.getResponseHeaders().add("Content-Type", "application/json");
        ex.sendResponseHeaders(status, b.length);
        ex.getResponseBody().write(b);
        ex.close();
    }

    private AkkomaSystemNoticeClient client(String token) {
        return new AkkomaSystemNoticeClient(
                WebClient.builder().baseUrl("http://127.0.0.1:" + server.getAddress().getPort()).build(),
                new SystemChannelTokens("", "", token, ""), Duration.ofSeconds(5));
    }

    private AkkomaSystemNoticeClient client() {
        return client(TOKEN);
    }

    @Test
    void happyPath_lookupThenDirectStatusStartingWithTheMention() {
        ChannelOutcome out = client().sendDirectNotice("alice", "Title\n\nBody", "row-1").block();

        assertThat(out).isEqualTo(ChannelOutcome.SENT);
        assertThat(requests).extracting(r -> r.method() + " " + r.path()).containsExactly(
                "GET /api/v1/accounts/lookup", "POST /api/v1/statuses");
        assertThat(requests.get(0).query()).isEqualTo("acct=alice");
        assertThat(requests).allSatisfy(r -> assertThat(r.bearer()).isEqualTo(TOKEN));
        JsonNode st = statuses.get(0);
        assertThat(st.get("visibility").asText()).isEqualTo("direct");
        assertThat(st.get("status").asText()).isEqualTo("@alice Title\n\nBody");
        assertThat(requests.get(1).idemKey()).isEqualTo("hm-row-1");
    }

    @Test
    void unknownAccount_isSkipped_andNothingIsPosted() {
        assertThat(client().sendDirectNotice("ghost", "x", "r").block()).isEqualTo(ChannelOutcome.SKIPPED);
        assertThat(statuses).isEmpty();
    }

    @Test
    void invalidLocalpart_isSkipped_withoutAnyRequest() {
        for (String bad : new String[] {null, "", " ", "al ice", "a&b=c", "alice@evil.test", "a".repeat(65)}) {
            assertThat(client().sendDirectNotice(bad, "x", "r").block()).as("localpart=%s", bad)
                    .isEqualTo(ChannelOutcome.SKIPPED);
        }
        assertThat(requests).isEmpty();
    }

    @Test
    void replyLostAfterCommit_retryWithSameKey_postsExactlyOneStatus() {
        AkkomaSystemNoticeClient c = client();
        dropNextPostReply = true;
        assertThat(c.sendDirectNotice("alice", "hello", "outbox-9").block()).isEqualTo(ChannelOutcome.FAILED);
        assertThat(statuses).hasSize(1);
        assertThat(c.sendDirectNotice("alice", "hello", "outbox-9").block()).isEqualTo(ChannelOutcome.SENT);
        assertThat(statuses).as("same Idempotency-Key => replayed, not re-posted").hasSize(1);
    }

    @Test
    void wrongToken_isFailed_andPostsNothing() {
        assertThat(client("nope").sendDirectNotice("alice", "x", "r").block()).isEqualTo(ChannelOutcome.FAILED);
        assertThat(statuses).isEmpty();
    }

    @Test
    void absentToken_isFailed_withoutAnyRequest() {
        assertThat(client("").sendDirectNotice("alice", "x", "r").block()).isEqualTo(ChannelOutcome.FAILED);
        assertThat(requests).isEmpty();
    }

    @Test
    void postErrors_areFailed_neverSent() {
        forcePostStatus = 422;
        assertThat(client().sendDirectNotice("alice", "x", "r").block()).isEqualTo(ChannelOutcome.FAILED);
        forcePostStatus = 503;
        assertThat(client().sendDirectNotice("alice", "x", "r").block()).isEqualTo(ChannelOutcome.FAILED);
        assertThat(statuses).isEmpty();
    }

    @Test
    void serverDown_isFailed_neverThrows() {
        AkkomaSystemNoticeClient c = client();
        server.stop(0);
        assertThat(c.sendDirectNotice("alice", "x", "r").block()).isEqualTo(ChannelOutcome.FAILED);
    }

    @Test
    void overlongBody_isTruncatedToTheCap_notRejected() {
        client().sendDirectNotice("alice", "y".repeat(9000), "r").block();
        assertThat(statuses.get(0).get("status").asText()).hasSize(AkkomaSystemNoticeClient.MAX_STATUS_CHARS);
        assertThat(statuses.get(0).get("status").asText()).startsWith("@alice yyy").endsWith("…");
    }

    // ── through the channel adapter ──────────────────────────────────────────
    @Test
    void channel_withRealTransport_sendsAndDoesNotNeedTheAnnouncementSeam() {
        net.hugmesh.adminbff.announcement.AnnouncementMastodonClient disabledSeam =
                new net.hugmesh.adminbff.announcement.AnnouncementMastodonClient(
                        WebClient.builder().baseUrl("http://x").build(), false);
        AkkomaChannel ch = new AkkomaChannel(disabledSeam, true, true, client());

        assertThat(ch.available("brandx").block()).isTrue();
        assertThat(ch.send("brandx", "hugmesh/Alice@brandx.test",
                new ChannelMessage("account-restriction", "T", "B", "row-3")).block())
                .isEqualTo(ChannelOutcome.SENT);
        assertThat(statuses.get(0).get("status").asText()).isEqualTo("@alice T\n\nB");
        assertThat(requests.get(1).idemKey()).isEqualTo("hm-row-3");
        // gate and token still required
        assertThat(new AkkomaChannel(disabledSeam, false, true, client()).available("d").block()).isFalse();
        assertThat(new AkkomaChannel(disabledSeam, true, false, client()).available("d").block()).isFalse();
        // and without the real transport the disabled seam keeps it unavailable, as before
        assertThat(new AkkomaChannel(disabledSeam, true, true).available("d").block()).isFalse();
    }
}
