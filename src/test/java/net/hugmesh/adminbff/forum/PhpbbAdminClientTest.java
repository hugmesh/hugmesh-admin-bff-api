package net.hugmesh.adminbff.forum;

import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.web.reactive.function.client.ClientRequest;
import org.springframework.web.reactive.function.client.ClientResponse;
import org.springframework.web.reactive.function.client.ExchangeFunction;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The forum-console client (admin-bff → forum-bff). Two behaviours are load-bearing:
 *
 * <ul>
 *   <li>SAFE/INERT default: {@code external.forum.enabled=false} → every verb returns
 *       {@link ForumOutcome#stubbed()} and makes NO network call (the current behaviour
 *       this feature preserves);</li>
 *   <li>UN-STUBBED: when enabled, the single {@code call()} seam makes the REAL
 *       JWT-forwarded ({@code Authorization: Bearer} + {@code X-HugMesh-JWT}) call to
 *       the forum-bff {@code /bff/forum/admin/**} contract, maps the JSON envelope into
 *       {@link ForumOutcome#ok}, and NEVER hard-fails — a transport error degrades.</li>
 * </ul>
 *
 * No live forum-bff / phpBB is needed: the WebClient is driven by a mock
 * {@link ExchangeFunction} recorder (the {@code FederationUsernameClientTest} pattern).
 */
class PhpbbAdminClientTest {

    private static final WebClient UNREACHABLE =
            WebClient.builder().baseUrl("http://forum-bff.invalid").build();
    private static final String JWT = "eyJ.forged.jwt";

    /** Records outgoing requests and replies with a canned forum-bff envelope body. */
    static class Recorder implements ExchangeFunction {
        final List<ClientRequest> requests = new ArrayList<>();
        String body = "{\"result\":\"ok\"}";
        HttpStatus status = HttpStatus.OK;
        boolean fail = false;

        @Override
        public Mono<ClientResponse> exchange(ClientRequest request) {
            requests.add(request);
            if (fail) {
                return Mono.error(new RuntimeException("connection refused"));
            }
            return Mono.just(ClientResponse.create(status)
                    .header("Content-Type", "application/json")
                    .body(body).build());
        }
    }

    private PhpbbAdminClient enabled(Recorder rec) {
        // Mirror ForumAdminConfig: EncodingMode.NONE so the enc()-encoded path segments
        // are sent verbatim (no double-encoding).
        org.springframework.web.util.DefaultUriBuilderFactory uriFactory =
                new org.springframework.web.util.DefaultUriBuilderFactory("http://forum-bff");
        uriFactory.setEncodingMode(org.springframework.web.util.DefaultUriBuilderFactory.EncodingMode.NONE);
        WebClient web = WebClient.builder().uriBuilderFactory(uriFactory)
                .baseUrl("http://forum-bff").exchangeFunction(rec).build();
        return new PhpbbAdminClient(web, true);
    }

    // ── SAFE/INERT default: disabled never calls, returns stubbed ───────

    @Test
    void disabled_everyVerb_isStubbed_neverThrows() {
        PhpbbAdminClient c = new PhpbbAdminClient(UNREACHABLE, false);
        assertThat(c.enabled()).isFalse();

        assertStubbed(c.stats(JWT));
        assertStubbed(c.listUsers(JWT));
        assertStubbed(c.getUser(JWT, "u-1"));
        assertStubbed(c.banUser(JWT, "u-1", "spam"));
        assertStubbed(c.unbanUser(JWT, "u-1"));
        assertStubbed(c.assignGroup(JWT, "u-1", "GLOBAL_MODERATORS"));
        assertStubbed(c.listCategories(JWT));
        assertStubbed(c.createCategory(JWT, Map.of("name", "General")));
        assertStubbed(c.moderationQueue(JWT));
        assertStubbed(c.approve(JWT, "p-1"));
        assertStubbed(c.reject(JWT, "p-1"));
        assertStubbed(c.installStyle(JWT, Map.of("name", "prosilver")));
        assertStubbed(c.installExtension(JWT, Map.of("name", "hugmesh/forum-api")));
        assertStubbed(c.audit(JWT));
    }

    @Test
    void disabled_makesNoNetworkCall() {
        Recorder rec = new Recorder();
        WebClient web = WebClient.builder().baseUrl("http://forum-bff").exchangeFunction(rec).build();
        new PhpbbAdminClient(web, false).stats(JWT).block();
        assertThat(rec.requests).isEmpty();
    }

    @Test
    void stubbed_tolerates_nullJwt_and_nullReason() {
        PhpbbAdminClient c = new PhpbbAdminClient(UNREACHABLE, false);
        assertStubbed(c.banUser(null, "u-1", null));
        assertStubbed(c.stats(null));
    }

    // ── enabled: real call, JWT forwarded, envelope mapped ──────────────

    @Test
    void enabled_get_callsForumBff_forwardsJwt_mapsOk() {
        Recorder rec = new Recorder();
        rec.body = "{\"topics\":12,\"posts\":40,\"result\":\"ok\"}";
        ForumOutcome out = enabled(rec).stats(JWT).block();

        assertThat(out).isNotNull();
        assertThat(out.isOk()).isTrue();
        assertThat(out.payload()).containsEntry("topics", 12);
        assertThat(rec.requests).hasSize(1);
        ClientRequest req = rec.requests.get(0);
        assertThat(req.method().name()).isEqualTo("GET");
        assertThat(req.url().getPath()).isEqualTo("/bff/forum/admin/stats");
        assertThat(req.headers().getFirst(HttpHeaders.AUTHORIZATION)).isEqualTo("Bearer " + JWT);
        assertThat(req.headers().getFirst("X-HugMesh-JWT")).isEqualTo(JWT);
    }

    @Test
    void enabled_listUsers_targetsTheUsersPath() {
        Recorder rec = new Recorder();
        rec.body = "{\"users\":[]}";
        enabled(rec).listUsers(JWT).block();
        assertThat(rec.requests.get(0).url().getPath()).isEqualTo("/bff/forum/admin/users");
    }

    @Test
    void enabled_ban_postsToBanPath() {
        Recorder rec = new Recorder();
        ForumOutcome out = enabled(rec).banUser(JWT, "u-1", "spam").block();
        assertThat(out.isOk()).isTrue();
        ClientRequest req = rec.requests.get(0);
        assertThat(req.method().name()).isEqualTo("POST");
        assertThat(req.url().getPath()).isEqualTo("/bff/forum/admin/users/u-1/ban");
    }

    @Test
    void enabled_assignGroup_postsToGroupsPath() {
        Recorder rec = new Recorder();
        enabled(rec).assignGroup(JWT, "u-1", "GLOBAL_MODERATORS").block();
        ClientRequest req = rec.requests.get(0);
        assertThat(req.method().name()).isEqualTo("POST");
        assertThat(req.url().getPath()).isEqualTo("/bff/forum/admin/users/u-1/groups");
    }

    @Test
    void enabled_unban_deletesBanPath() {
        Recorder rec = new Recorder();
        enabled(rec).unbanUser(JWT, "u-1").block();
        ClientRequest req = rec.requests.get(0);
        assertThat(req.method().name()).isEqualTo("DELETE");
        assertThat(req.url().getPath()).isEqualTo("/bff/forum/admin/users/u-1/ban");
    }

    @Test
    void enabled_createCategory_postsToCategoriesPath() {
        Recorder rec = new Recorder();
        rec.body = "{\"state\":\"created\",\"result\":\"ok\"}";
        enabled(rec).createCategory(JWT, Map.of("name", "Ops")).block();
        ClientRequest req = rec.requests.get(0);
        assertThat(req.method().name()).isEqualTo("POST");
        assertThat(req.url().getPath()).isEqualTo("/bff/forum/admin/categories");
    }

    @Test
    void enabled_approveReject_targetModerationPaths() {
        Recorder rec = new Recorder();
        enabled(rec).approve(JWT, "p-1").block();
        enabled(rec).reject(JWT, "p-1").block();
        assertThat(rec.requests.get(0).url().getPath()).isEqualTo("/bff/forum/admin/moderation/p-1/approve");
        assertThat(rec.requests.get(1).url().getPath()).isEqualTo("/bff/forum/admin/moderation/p-1/reject");
    }

    @Test
    void enabled_idEncoded_inPath() {
        Recorder rec = new Recorder();
        enabled(rec).getUser(JWT, "weird id/with+chars").block();
        // The id segment is URL-encoded by the client (enc()).
        assertThat(rec.requests.get(0).url().getRawPath()).contains("weird+id%2Fwith%2Bchars");
    }

    // ── NEVER hard-fail: a transport error degrades (never throws) ──────

    @Test
    void enabled_transportError_degradesNeverThrows() {
        Recorder rec = new Recorder();
        rec.fail = true;
        ForumOutcome out = enabled(rec).stats(JWT).block();

        assertThat(out).isNotNull();
        assertThat(out.isOk()).isFalse();
        assertThat(out.isStubbed()).isFalse();
        assertThat(out.result()).startsWith("degraded");
    }

    /**
     * A degenerate empty/no-JSON body NEVER throws — it resolves to a non-null outcome
     * (forum-bff write endpoints always return a JSON envelope; this proves the client is
     * robust to a body it cannot decode and the admin request still completes).
     */
    @Test
    void enabled_emptyBody_neverThrows() {
        Recorder rec = new Recorder();
        rec.body = "";
        ForumOutcome out = enabled(rec).unbanUser(JWT, "u-1").block();
        assertThat(out).isNotNull();
        assertThat(out.isStubbed()).isFalse();
    }

    /** No JWT principal (mock-authority test) → no auth header, still calls. */
    @Test
    void enabled_nullJwt_omitsAuthHeader() {
        Recorder rec = new Recorder();
        enabled(rec).stats(null).block();
        ClientRequest req = rec.requests.get(0);
        assertThat(req.headers().getFirst(HttpHeaders.AUTHORIZATION)).isNull();
        assertThat(req.headers().getFirst("X-HugMesh-JWT")).isNull();
    }

    private static void assertStubbed(Mono<ForumOutcome> mono) {
        ForumOutcome outcome = mono.block();
        assertThat(outcome).isNotNull();
        assertThat(outcome.isStubbed()).isTrue();
        assertThat(outcome.isOk()).isFalse();
        // The console envelope always carries the result marker.
        assertThat(outcome.asResponse()).containsEntry("result", "stubbed");
    }
}
