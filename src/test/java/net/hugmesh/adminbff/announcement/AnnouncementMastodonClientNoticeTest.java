package net.hugmesh.adminbff.announcement;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.web.reactive.function.client.WebClient;
import net.hugmesh.adminbff.notification.AccountRestrictionPayload;
import net.hugmesh.adminbff.notification.NotificationOutbox;
import net.hugmesh.adminbff.notification.NotificationTemplate;
import net.hugmesh.adminbff.notification.channel.AkkomaChannel;
import net.hugmesh.adminbff.notification.channel.ChannelMessage;
import net.hugmesh.adminbff.notification.channel.ChannelOutcome;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.time.Duration;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.SoftAssertions.assertSoftly;

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
    /** The accounts the fake instance knows; only {@code alice} is ever the recipient. */
    private static final List<String> ACCOUNTS = List.of("alice", "bob", "carol");

    record Seen(String method, String path, String authorization, JsonNode body) { }

    private HttpServer server;
    private final List<Seen> requests = Collections.synchronizedList(new ArrayList<>());
    private volatile int status = 200;
    private volatile String replyBody = "{\"id\":\"9\",\"visibility\":\"direct\"}";
    /** Non-null while the fake must take the request and then say nothing. */
    private volatile CountDownLatch silent;

    @BeforeEach
    void up() throws IOException {
        server = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
        server.createContext("/", this::handle);
        server.start();
    }

    @AfterEach
    void down() {
        CountDownLatch held = silent;
        if (held != null) {
            held.countDown();
        }
        server.stop(0);
    }

    private void handle(HttpExchange ex) throws IOException {
        String raw = new String(ex.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
        requests.add(new Seen(ex.getRequestMethod(), ex.getRequestURI().getPath(),
                ex.getRequestHeaders().getFirst("Authorization"),
                raw.isBlank() ? MAPPER.createObjectNode() : MAPPER.readTree(raw)));
        CountDownLatch held = silent;
        if (held != null) {
            awaitQuietly(held);
            ex.close();
            return;
        }
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

    private static void awaitQuietly(CountDownLatch latch) {
        try {
            latch.await(30, TimeUnit.SECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
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
                ADMIN_TOKEN, SYSTEM_TOKEN, 10_000L);
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

    // ── the notice must reach the recipient and nobody else ──────────────────

    /** The text of the one status the fake received. */
    private String onlyStatus() {
        assertThat(requests).hasSize(1);
        return requests.get(0).body().path("status").asText();
    }

    @Test
    void aReasonThatNamesSomeoneElse_cannotAddARecipient() {
        assertSoftly(soft -> {
            for (String reason : FediverseAddressing.REASONS_NAMING_SOMEONE_ELSE) {
                requests.clear();
                AkkomaOutcome out = client(true, null, SYSTEM_TOKEN).postLocalUserNotice("alice",
                        "Your account access changed\n\nReason: " + reason + ".").block();
                soft.assertThat(out.isOk()).as("reason=[%s] posted", reason).isTrue();
                String status = onlyStatus();
                // Parser-independent: the recipient's own mention is the only at-sign there is.
                soft.assertThat(status).as("reason=[%s]", reason).startsWith("@alice Your account access changed");
                soft.assertThat(FediverseAddressing.atSigns(status)).as("at-signs in [%s]", status).isEqualTo(1);
                // And a server that reads recipients out of the text finds only alice.
                soft.assertThat(FediverseAddressing.addressedByText(status, ACCOUNTS))
                        .as("addressed by [%s]", status).containsExactly("alice");
            }
        });
    }

    @Test
    void aReasonThatCarriesATag_isPostedWithNoLessThanSign() {
        assertSoftly(soft -> {
            for (String reason : FediverseAddressing.REASONS_CARRYING_A_TAG) {
                requests.clear();
                client(true, null, SYSTEM_TOKEN).postLocalUserNotice("alice", "T\n\nReason: " + reason + ".")
                        .block();
                String status = onlyStatus();
                // Nothing in the status can open a tag, however a server escapes plain text.
                soft.assertThat(FediverseAddressing.lessThans(status)).as("less-than signs in [%s]", status)
                        .isZero();
                soft.assertThat(FediverseAddressing.atSigns(status)).as("at-signs in [%s]", status).isEqualTo(1);
            }
        });
    }

    @Test
    void throughTheRealTemplateAndChannel_aModeratorReasonCannotAddARecipient() {
        String payload = AccountRestrictionPayload.build("hugmesh/alice", "PROFILE", 3600L,
                "reported by @carol, see @bob@remote.social");
        NotificationTemplate.Message msg =
                NotificationTemplate.render(NotificationOutbox.CATEGORY_ACCOUNT_RESTRICTION, payload);

        ChannelOutcome out = new AkkomaChannel(client(true, null, SYSTEM_TOKEN), true, true)
                .send("brandx", "hugmesh/alice", new ChannelMessage(
                        NotificationOutbox.CATEGORY_ACCOUNT_RESTRICTION, msg.title(), msg.body(), "row-7"))
                .block();

        assertThat(out).isEqualTo(ChannelOutcome.SENT);
        String status = onlyStatus();
        assertThat(status).startsWith("@alice Your account access changed\n\n");
        assertThat(status).contains("Reason: reported by (at)carol, see (at)bob(at)remote.social.");
        assertThat(FediverseAddressing.atSigns(status)).isEqualTo(1);
        assertThat(FediverseAddressing.addressedByText(status, ACCOUNTS)).containsExactly("alice");
    }

    @Test
    void theRecipientIsAlsoNamedInTheToField() {
        // Akkoma addresses exactly the nicknames in "to" and then ignores mentions in the
        // text (read from its source, not observed live); other servers ignore the field.
        client(true, null, SYSTEM_TOKEN).postLocalUserNotice("alice", "T\n\nReason: @carol.").block();

        JsonNode to = requests.get(0).body().path("to");
        assertThat(to.isArray()).as("to=%s", to).isTrue();
        assertThat(to).hasSize(1);
        assertThat(to.get(0).asText()).isEqualTo("alice");
    }

    @Test
    void aRecipientNameAParserWouldShortenOrSplit_isNeverPosted() {
        // "@bob." and "@bob," reach bob on both servers and "@bob-" does on Mastodon, so a
        // name that is not letters, digits and underscores throughout is refused outright.
        for (String lp : new String[] {"bob.", "bob..", "bob-", ".bob", "-bob", "bob.smith", "b-ob",
            "bob,", "bob!", "bob)", "bob/", "bob's", "bob\tx", "bob\u200B"}) {
            AkkomaOutcome out = client(true, null, SYSTEM_TOKEN).postLocalUserNotice(lp, "x").block();
            assertThat(out.result()).as("localpart=[%s]", lp).startsWith("degraded:");
        }
        assertThat(requests).isEmpty();
    }

    @Test
    void throughTheChannel_aNameNoAccountCanHave_isSkippedWithoutAnyRequest() {
        // Terminal, not a retry: no later attempt can make such a name deliverable.
        for (String subject : new String[] {"hugmesh/bob.", "hugmesh/Bob-", "bob.smith@brandx.test",
            "hugmesh/b ob", "hugmesh/" + "a".repeat(65)}) {
            ChannelOutcome out = new AkkomaChannel(client(true, null, SYSTEM_TOKEN), true, true)
                    .send("brandx", subject, new ChannelMessage("c", "T", "B")).block();
            assertThat(out).as("subject=[%s]", subject).isEqualTo(ChannelOutcome.SKIPPED);
        }
        assertThat(requests).isEmpty();
    }

    @Test
    void sixtyFourCharactersIsTheLongestRecipientName() {
        assertThat(client(true, null, SYSTEM_TOKEN).postLocalUserNotice("a".repeat(64), "x").block().isOk())
                .isTrue();
        assertThat(client(true, null, SYSTEM_TOKEN).postLocalUserNotice("a".repeat(65), "x").block().result())
                .startsWith("degraded:");
        assertThat(requests).hasSize(1);
    }

    @Test
    void overlongNotice_isCappedNotRejected() {
        client(true, null, SYSTEM_TOKEN).postLocalUserNotice("alice", "y".repeat(9000)).block();

        assertThat(onlyStatus()).hasSize(4000).startsWith("@alice yyy").endsWith("\u2026");
    }

    // ── a server that never answers ──────────────────────────────────────────

    @Test
    void aServerThatNeverAnswers_isDegradedAfterTheTimeout_notAHangingSend() {
        silent = new CountDownLatch(1);
        AnnouncementMastodonClient impatient = new AnnouncementMastodonClient(
                WebClient.builder().baseUrl("http://127.0.0.1:" + server.getAddress().getPort()).build(),
                true, null, SYSTEM_TOKEN, Duration.ofMillis(300));

        long started = System.nanoTime();
        // block(5 s) so that a send with no timeout fails this test and does not hang it.
        AkkomaOutcome out = impatient.postLocalUserNotice("alice", "x").block(Duration.ofSeconds(5));

        assertThat(out.result()).startsWith("degraded:");
        assertThat(out.isOk()).isFalse();
        assertThat(Duration.ofNanos(System.nanoTime() - started)).isLessThan(Duration.ofSeconds(4));
        assertThat(requests).hasSize(1);
    }

    @Test
    void configBean_passesTheNoticeTimeoutThrough() {
        silent = new CountDownLatch(1);
        AnnouncementMastodonClient bean = new AnnouncementConfig().announcementMastodonClient(
                WebClient.builder(), "http://127.0.0.1:" + server.getAddress().getPort(), true,
                ADMIN_TOKEN, SYSTEM_TOKEN, 300L);

        AkkomaOutcome out = bean.postLocalUserNotice("alice", "x").block(Duration.ofSeconds(5));

        assertThat(out.result()).startsWith("degraded:");
    }

    @Test
    void aNullTimeout_fallsBackToTheDefault_andStillSends() {
        AkkomaOutcome out = new AnnouncementMastodonClient(
                WebClient.builder().baseUrl("http://127.0.0.1:" + server.getAddress().getPort()).build(),
                true, null, SYSTEM_TOKEN, null).postLocalUserNotice("alice", "x").block(Duration.ofSeconds(5));

        assertThat(out.isOk()).isTrue();
    }
}
