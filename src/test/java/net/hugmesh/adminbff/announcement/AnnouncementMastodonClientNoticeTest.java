package net.hugmesh.adminbff.announcement;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.web.reactive.function.client.WebClient;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The {@code @system} per-user notice leg of {@link AnnouncementMastodonClient}
 * ({@link AnnouncementMastodonClient#postLocalUserNotice}) against an in-JVM Mastodon-API
 * fake: what goes on the wire (path, {@code visibility=direct}, mention text, the
 * {@code @system} bearer and never the admin one), that both gates keep it STUBBED with
 * ZERO requests, and that every non-2xx resolves degraded. The fake's reply shapes come
 * from the Mastodon API documentation; no running Akkoma was used.
 */
class AnnouncementMastodonClientNoticeTest {

    private static final String SYSTEM_TOKEN = "system-account-token";
    private static final String ADMIN_TOKEN = "admin-bearer";
    private static final ObjectMapper MAPPER = new ObjectMapper();

    record Seen(String method, String path, String authorization, JsonNode body) { }

    private HttpServer server;
    private final List<Seen> requests = Collections.synchronizedList(new ArrayList<>());
    private volatile int status = 200;
    private volatile String replyBody = "{\"id\":\"9\",\"visibility\":\"direct\"}";

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
        String raw = new String(ex.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
        requests.add(new Seen(ex.getRequestMethod(), ex.getRequestURI().getPath(),
                ex.getRequestHeaders().getFirst("Authorization"),
                raw.isBlank() ? MAPPER.createObjectNode() : MAPPER.readTree(raw)));
        if (status >= 300 && status < 400) {
            ex.getResponseHeaders().add("Location", "https://akkoma.invalid" + ex.getRequestURI());
            ex.sendResponseHeaders(status, -1);
            ex.close();
            return;
        }
        byte[] b = replyBody.getBytes(StandardCharsets.UTF_8);
        ex.getResponseHeaders().add("Content-Type", "application/json");
        ex.sendResponseHeaders(status, b.length);
        ex.getResponseBody().write(b);
        ex.close();
    }

    private AnnouncementMastodonClient client(boolean enabled, String adminToken, String systemToken) {
        return new AnnouncementMastodonClient(
                WebClient.builder().baseUrl("http://127.0.0.1:" + server.getAddress().getPort()).build(),
                enabled, adminToken, systemToken);
    }

    @Test
    void enabled_withSystemToken_postsDirectStatus_mentioningTheRecipient() {
        AkkomaOutcome out = client(true, null, SYSTEM_TOKEN)
                .postLocalUserNotice("alice", "Account restricted\n\nUntil Friday").block();

        assertThat(out).isNotNull();
        assertThat(out.isOk()).isTrue();
        assertThat(out.isStubbed()).isFalse();
        assertThat(requests).hasSize(1);
        Seen post = requests.get(0);
        assertThat(post.method()).isEqualTo("POST");
        assertThat(post.path()).isEqualTo("/api/v1/statuses");
        assertThat(post.body().path("visibility").asText()).isEqualTo("direct");
        assertThat(post.body().path("status").asText()).isEqualTo("@alice Account restricted\n\nUntil Friday");
        assertThat(post.authorization()).isEqualTo("Bearer " + SYSTEM_TOKEN);
    }

    @Test
    void notice_usesTheSystemToken_neverTheAdminBearer() {
        AkkomaOutcome out = client(true, ADMIN_TOKEN, SYSTEM_TOKEN).postLocalUserNotice("bob", "hi").block();

        assertThat(out.isOk()).isTrue();
        assertThat(requests).hasSize(1);
        assertThat(requests.get(0).authorization()).isEqualTo("Bearer " + SYSTEM_TOKEN);
    }

    @Test
    void disabled_isStubbed_andIssuesNoHttp_evenWithTheToken() {
        AkkomaOutcome out = client(false, ADMIN_TOKEN, SYSTEM_TOKEN).postLocalUserNotice("alice", "x").block();

        assertThat(out.isStubbed()).isTrue();
        assertThat(out.isOk()).isFalse();
        assertThat(requests).isEmpty();
    }

    @Test
    void enabled_withoutSystemToken_isStubbed_andIssuesNoHttp() {
        // The admin bearer alone must NOT be enough: the notice is posted as @system.
        for (String token : new String[] {null, "", "   "}) {
            AkkomaOutcome out = client(true, ADMIN_TOKEN, token).postLocalUserNotice("alice", "x").block();
            assertThat(out.isStubbed()).as("token=[%s]", token).isTrue();
        }
        assertThat(requests).isEmpty();
        // The legacy two/three-arg constructors carry no @system token, so they stay stubbed too.
        WebClient web = WebClient.builder().baseUrl("http://127.0.0.1:" + server.getAddress().getPort()).build();
        assertThat(new AnnouncementMastodonClient(web, true).postLocalUserNotice("alice", "x").block().isStubbed())
                .isTrue();
        assertThat(new AnnouncementMastodonClient(web, true, ADMIN_TOKEN).postLocalUserNotice("alice", "x")
                .block().isStubbed()).isTrue();
        assertThat(requests).isEmpty();
    }

    @Test
    void non2xx_resolvesDegraded_neverOkAndNeverThrows() {
        for (int code : new int[] {401, 404, 422, 500, 503, 308}) {
            status = code;
            AkkomaOutcome out = client(true, null, SYSTEM_TOKEN).postLocalUserNotice("alice", "x").block();
            assertThat(out).as("HTTP %d", code).isNotNull();
            assertThat(out.isOk()).as("HTTP %d", code).isFalse();
            assertThat(out.isStubbed()).as("HTTP %d", code).isFalse();
            assertThat(out.result()).as("HTTP %d", code).startsWith("degraded:");
        }
        assertThat(requests).hasSize(6);
    }

    @Test
    void serverDown_resolvesDegraded() {
        int port = server.getAddress().getPort();
        server.stop(0);
        AkkomaOutcome out = new AnnouncementMastodonClient(
                WebClient.builder().baseUrl("http://127.0.0.1:" + port).build(), true, null, SYSTEM_TOKEN)
                .postLocalUserNotice("alice", "x").block();
        assertThat(out.result()).startsWith("degraded:");
    }

    @Test
    void localpartThatCouldSmuggleAMention_isRefusedBeforeAnyHttp() {
        for (String lp : new String[] {"alice @bob", "alice\n@bob", "", "Alice", "a@b"}) {
            AkkomaOutcome out = client(true, null, SYSTEM_TOKEN).postLocalUserNotice(lp, "x").block();
            assertThat(out.result()).as("localpart=[%s]", lp).startsWith("degraded:");
        }
        assertThat(client(true, null, SYSTEM_TOKEN).postLocalUserNotice(null, "x").block().result())
                .startsWith("degraded:");
        assertThat(requests).isEmpty();
    }

    @Test
    void configBean_passesTheSystemTokenThrough_notTheAdminToken() {
        AnnouncementMastodonClient bean = new AnnouncementConfig().announcementMastodonClient(
                WebClient.builder(), "http://127.0.0.1:" + server.getAddress().getPort(), true,
                ADMIN_TOKEN, SYSTEM_TOKEN);
        assertThat(bean.postLocalUserNotice("alice", "x").block().isOk()).isTrue();
        assertThat(requests.get(0).authorization()).isEqualTo("Bearer " + SYSTEM_TOKEN);
    }

    @Test
    void throughTheChannel_okIsSent_andAMissingTokenIsAFailedRetry() {
        var sent = new net.hugmesh.adminbff.notification.channel.AkkomaChannel(
                client(true, null, SYSTEM_TOKEN), true, true)
                .send("brandx", "hugmesh/Alice@brandx.test",
                        new net.hugmesh.adminbff.notification.channel.ChannelMessage("c", "T", "B"))
                .block();
        assertThat(sent).isEqualTo(net.hugmesh.adminbff.notification.channel.ChannelOutcome.SENT);
        assertThat(requests.get(0).body().path("status").asText()).isEqualTo("@alice T\n\nB");

        var noToken = new net.hugmesh.adminbff.notification.channel.AkkomaChannel(
                client(true, null, null), true, true)
                .send("brandx", "alice", new net.hugmesh.adminbff.notification.channel.ChannelMessage("c", "T", "B"))
                .block();
        assertThat(noToken).isEqualTo(net.hugmesh.adminbff.notification.channel.ChannelOutcome.FAILED);
        assertThat(requests).hasSize(1);
    }

    @Test
    void nullBody_postsTheBareMention() {
        client(true, null, SYSTEM_TOKEN).postLocalUserNotice("alice", null).block();
        assertThat(requests.get(0).body().path("status").asText()).isEqualTo("@alice ");
    }
}
