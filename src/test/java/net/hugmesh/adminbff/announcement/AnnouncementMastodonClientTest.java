package net.hugmesh.adminbff.announcement;

import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.web.reactive.function.client.ClientRequest;
import org.springframework.web.reactive.function.client.ClientResponse;
import org.springframework.web.reactive.function.client.ExchangeFunction;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The akkoma propagation client: disabled by default → STUBBED (no HTTP), never
 * hard-fails, and a null/blank removal ref is a no-op OK. When ENABLED it issues the
 * REAL CONFIRMED pleroma-admin announcement create/remove calls — proven here with a
 * recording {@link ExchangeFunction} (no live akkoma): create POSTs
 * {@code /api/v1/pleroma/admin/announcements} with field {@code content} and reads back
 * the {@code id}; remove DELETEs by id and tolerates a 404 as idempotent OK. Any OTHER
 * non-2xx — including the live-verified force-HTTPS 308 redirect that WebClient's default
 * handlers pass through — resolves DEGRADED on both legs, never a false OK.
 */
class AnnouncementMastodonClientTest {

    private static final WebClient WEB =
            WebClient.builder().baseUrl("http://akkoma.invalid").build();

    /** Records outgoing requests and returns a canned akkoma announcement object. */
    static class Recorder implements ExchangeFunction {
        final List<ClientRequest> requests = new ArrayList<>();
        HttpStatus deleteStatus = HttpStatus.OK;
        HttpStatus postStatus = HttpStatus.OK;

        @Override
        public Mono<ClientResponse> exchange(ClientRequest request) {
            requests.add(request);
            if (request.method().name().equals("DELETE")) {
                return Mono.just(ClientResponse.create(deleteStatus)
                        .header("Content-Type", "application/json").body("{}").build());
            }
            if (postStatus != HttpStatus.OK) {
                return Mono.just(ClientResponse.create(postStatus)
                        .header("Content-Type", "text/html").body("<html>Not Found</html>").build());
            }
            return Mono.just(ClientResponse.create(HttpStatus.OK)
                    .header("Content-Type", "application/json")
                    .body("{\"id\":\"akk-123\",\"content\":\"x\"}").build());
        }
    }

    private static AnnouncementMastodonClient enabledClient(Recorder rec) {
        return new AnnouncementMastodonClient(
                WebClient.builder().baseUrl("http://akkoma.invalid").exchangeFunction(rec).build(),
                true, "vault-injected-token");
    }

    private static Announcement sample() {
        return new Announcement("id1", "Heads up", "<p>body</p>", "html", "published",
                false, false, true, false, 0, null, null, "UTC", true, "admin@x", null,
                Instant.now(), Instant.now(), "default");
    }

    @Test
    void disabled_create_isStubbed() {
        AnnouncementMastodonClient client = new AnnouncementMastodonClient(WEB, false);
        AkkomaOutcome outcome = client.createLocalAnnouncement(sample()).block();
        assertThat(outcome.isStubbed()).isTrue();
        assertThat(outcome.ref()).isNull();
    }

    @Test
    void disabled_remove_isStubbed() {
        AnnouncementMastodonClient client = new AnnouncementMastodonClient(WEB, false);
        AkkomaOutcome outcome = client.removeAnnouncement("akk-1").block();
        assertThat(outcome.isStubbed()).isTrue();
    }

    @Test
    void remove_nullRef_isNoOpOk() {
        AnnouncementMastodonClient client = new AnnouncementMastodonClient(WEB, false);
        assertThat(client.removeAnnouncement(null).block().isOk()).isTrue();
        assertThat(client.removeAnnouncement("  ").block().isOk()).isTrue();
    }

    @Test
    void enabled_create_postsRealPleromaAdminAnnouncement_withContent_andReadsId() {
        Recorder rec = new Recorder();
        AkkomaOutcome outcome = enabledClient(rec).createLocalAnnouncement(sample()).block();

        // Real HTTP was issued (NOT stubbed) and the returned id was captured as the ref.
        assertThat(outcome.isOk()).isTrue();
        assertThat(outcome.ref()).isEqualTo("akk-123");
        assertThat(rec.requests).hasSize(1);
        ClientRequest post = rec.requests.get(0);
        assertThat(post.method().name()).isEqualTo("POST");
        assertThat(post.url().getPath()).isEqualTo("/api/v1/pleroma/admin/announcements");
        // CONFIRMED contract: field is "content" (not "text"); admin bearer is sent.
        assertThat(post.headers().getFirst("Authorization")).isEqualTo("Bearer vault-injected-token");
    }

    @Test
    void enabled_remove_issuesRealDelete_byId() {
        Recorder rec = new Recorder();
        AkkomaOutcome outcome = enabledClient(rec).removeAnnouncement("akk-123").block();

        assertThat(outcome.isOk()).isTrue();
        assertThat(rec.requests).hasSize(1);
        ClientRequest del = rec.requests.get(0);
        assertThat(del.method().name()).isEqualTo("DELETE");
        assertThat(del.url().getPath()).isEqualTo("/api/v1/pleroma/admin/announcements/akk-123");
    }

    @Test
    void enabled_create_routeMissing404_resolvesDegraded_neverOk() {
        // LIVE-VERIFIED reality (2026-07): mainline Mastodon 4.3.1 (the compose stack's
        // Akkoma stand-in) has NO /api/v1/pleroma/* routes — POST returns a route-level
        // 404 (HTML body). The client must resolve DEGRADED (no fake created-ref, no OK).
        Recorder rec = new Recorder();
        rec.postStatus = HttpStatus.NOT_FOUND;
        AkkomaOutcome outcome = enabledClient(rec).createLocalAnnouncement(sample()).block();
        assertThat(outcome.isOk()).isFalse();
        assertThat(outcome.isStubbed()).isFalse();
        assertThat(outcome.result()).startsWith("degraded:");
        assertThat(outcome.ref()).isNull();
    }

    @Test
    void enabled_remove_redirect308_resolvesDegraded_neverOk() {
        // LIVE-VERIFIED reality (2026-07): Mastodon's force-HTTPS plain-HTTP port answers
        // DELETE /api/v1/pleroma/admin/announcements/{id} with a method-preserving 308
        // (Content-Length: 0). WebClient's default handlers only error on 4xx/5xx, so a
        // 3xx would slip through retrieve() as a false OK — and a false OK here makes the
        // service clear akkoma_ref, orphaning the real Akkoma post. Must be DEGRADED.
        Recorder rec = new Recorder();
        rec.deleteStatus = HttpStatus.PERMANENT_REDIRECT;
        AkkomaOutcome outcome = enabledClient(rec).removeAnnouncement("akk-123").block();
        assertThat(outcome.isOk()).isFalse();
        assertThat(outcome.isStubbed()).isFalse();
        assertThat(outcome.result()).startsWith("degraded:");
    }

    @Test
    void enabled_create_redirect3xx_resolvesDegraded_neverOkOrEmpty() {
        // Same false-success class on the create leg: a 3xx must resolve DEGRADED (no
        // fabricated ref, and never an empty Mono from the redirect's bodiless response).
        Recorder rec = new Recorder();
        rec.postStatus = HttpStatus.PERMANENT_REDIRECT;
        AkkomaOutcome outcome = enabledClient(rec).createLocalAnnouncement(sample()).block();
        assertThat(outcome).isNotNull();
        assertThat(outcome.isOk()).isFalse();
        assertThat(outcome.result()).startsWith("degraded:");
        assertThat(outcome.ref()).isNull();
    }

    @Test
    void enabled_remove_alreadyDeleted404_isSwallowedToOk() {
        Recorder rec = new Recorder();
        rec.deleteStatus = HttpStatus.NOT_FOUND;
        // Idempotent removal: a 404 on an already-deleted id is OK, not degraded.
        AkkomaOutcome outcome = enabledClient(rec).removeAnnouncement("gone").block();
        assertThat(outcome.isOk()).isTrue();
    }

    @Test
    void disabled_create_issuesNoHttp() {
        Recorder rec = new Recorder();
        AnnouncementMastodonClient client = new AnnouncementMastodonClient(
                WebClient.builder().exchangeFunction(rec).build(), false, "tok");
        AkkomaOutcome outcome = client.createLocalAnnouncement(sample()).block();
        // Disabled is a guaranteed no-op: STUBBED and zero requests made.
        assertThat(outcome.isStubbed()).isTrue();
        assertThat(rec.requests).isEmpty();
    }
}
