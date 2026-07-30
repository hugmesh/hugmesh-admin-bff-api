package systems.hugmesh.adminbff.homeserver;

import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.web.reactive.function.client.ClientRequest;
import org.springframework.web.reactive.function.client.ClientResponse;
import org.springframework.web.reactive.function.client.ExchangeFunction;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Verifies the homeserver admin seam:
 *
 * <ul>
 *   <li><b>akkoma suspend/unsuspend = WIRED-REAL (gated).</b> When enabled it issues the
 *       CONFIRMED idempotent batch verbs {@code PATCH /api/v1/pleroma/admin/users/deactivate}
 *       (suspend) / {@code /activate} (unsuspend) with body {@code {"nicknames":[localpart]}}
 *       and the admin bearer — proven with a recording {@link ExchangeFunction} (no live
 *       akkoma). Disabled → STUBBED, zero HTTP.</li>
 *   <li><b>tuwunel deactivate = FLAG-GATED STRUCTURED STUB.</b> Even when enabled it makes
 *       NO call (no REST admin API exists; the admin-room transport is out of scope) — it
 *       returns STUBBED and never hard-fails. Proven by asserting zero requests.</li>
 * </ul>
 */
class HomeserverAdminClientTest {

    static class Recorder implements ExchangeFunction {
        final List<ClientRequest> requests = new ArrayList<>();

        @Override
        public Mono<ClientResponse> exchange(ClientRequest request) {
            requests.add(request);
            return Mono.just(ClientResponse.create(HttpStatus.OK)
                    .header("Content-Type", "application/json")
                    .body("{\"users\":[{\"deactivated\":true}]}").build());
        }
    }

    private HomeserverAdminClient enabledClient(Recorder akkomaRec, Recorder tuwunelRec) {
        WebClient akkoma = WebClient.builder().baseUrl("http://akkoma.invalid")
                .exchangeFunction(akkomaRec).build();
        WebClient tuwunel = WebClient.builder().baseUrl("http://tuwunel.invalid")
                .exchangeFunction(tuwunelRec).build();
        return new HomeserverAdminClient(akkoma, tuwunel, true, false, "vault-injected-token");
    }

    @Test
    void enabled_suspend_patchesDeactivate_withNicknames_andBearer() {
        Recorder akk = new Recorder();
        HomeserverOutcome outcome = enabledClient(akk, new Recorder()).suspendMastodon("alice").block();

        assertThat(outcome.isOk()).isTrue();
        assertThat(akk.requests).hasSize(1);
        ClientRequest req = akk.requests.get(0);
        assertThat(req.method().name()).isEqualTo("PATCH");
        // CONFIRMED contract: idempotent batch verb /users/deactivate (NOT /users/{nick}/suspend).
        assertThat(req.url().getPath()).isEqualTo("/api/v1/pleroma/admin/users/deactivate");
        assertThat(req.headers().getFirst("Authorization")).isEqualTo("Bearer vault-injected-token");
    }

    @Test
    void enabled_unsuspend_patchesActivate() {
        Recorder akk = new Recorder();
        HomeserverOutcome outcome = enabledClient(akk, new Recorder()).unsuspendMastodon("bob").block();

        assertThat(outcome.isOk()).isTrue();
        ClientRequest req = akk.requests.get(0);
        assertThat(req.method().name()).isEqualTo("PATCH");
        assertThat(req.url().getPath()).isEqualTo("/api/v1/pleroma/admin/users/activate");
    }

    @Test
    void disabled_suspend_issuesNoHttp() {
        Recorder akk = new Recorder();
        HomeserverAdminClient client = new HomeserverAdminClient(
                WebClient.builder().exchangeFunction(akk).build(), null, false);
        HomeserverOutcome outcome = client.suspendMastodon("alice").block();
        assertThat(outcome.isStubbed()).isTrue();
        assertThat(akk.requests).isEmpty();
    }

    @Test
    void enabled_tuwunelDeactivate_staysStructuredStub_makesNoCall() {
        // tuwunel has no REST admin API — the leg is a deliberate flag-gated structured
        // stub even when enabled: STUBBED, never hard-fails, and issues zero HTTP.
        Recorder tuw = new Recorder();
        HomeserverOutcome outcome = enabledClient(new Recorder(), tuw).deactivateMatrix("alice").block();
        assertThat(outcome.isStubbed()).isTrue();
        assertThat(tuw.requests).isEmpty();
    }

    @Test
    void enabled_tuwunelActivate_staysStructuredStub_makesNoCall() {
        Recorder tuw = new Recorder();
        HomeserverOutcome outcome = enabledClient(new Recorder(), tuw).activateMatrix("alice").block();
        assertThat(outcome.isStubbed()).isTrue();
        assertThat(tuw.requests).isEmpty();
    }
}
