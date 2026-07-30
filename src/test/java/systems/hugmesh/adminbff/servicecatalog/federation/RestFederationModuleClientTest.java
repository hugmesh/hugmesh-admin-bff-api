package systems.hugmesh.adminbff.servicecatalog.federation;

import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.mock.http.client.reactive.MockClientHttpRequest;
import org.springframework.web.reactive.function.client.ClientRequest;
import org.springframework.web.reactive.function.client.ClientResponse;
import org.springframework.web.reactive.function.client.ExchangeFunction;
import org.springframework.web.reactive.function.client.ExchangeStrategies;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Verifies the REAL federation-module client issues the recon-pinned federation-api admin calls,
 * driven by a recording {@link ExchangeFunction} that also SERIALISES the request body (via
 * {@link MockClientHttpRequest}) so the exact POST body is asserted — the register POSTs
 * {@code /api/federation/admin/modules} with the module fields, the unregister DELETEs
 * {@code /api/federation/admin/modules/{slug}} and tolerates a 404.
 */
class RestFederationModuleClientTest {

    /** A recorded request: method, path, and the serialised body. */
    record Captured(String method, String path, String body) {
    }

    static final class Recorder implements ExchangeFunction {
        final List<Captured> requests = new ArrayList<>();
        HttpStatus responseStatus = HttpStatus.OK;
        String responseBody = "{\"slug\":\"owncast\"}";

        @Override
        public Mono<ClientResponse> exchange(ClientRequest request) {
            MockClientHttpRequest mock = new MockClientHttpRequest(request.method(), request.url());
            request.writeTo(mock, ExchangeStrategies.withDefaults()).block();
            String body = mock.getBodyAsString().block();
            requests.add(new Captured(request.method().name(), request.url().getPath(), body));
            return Mono.just(ClientResponse.create(responseStatus)
                    .header("Content-Type", "application/json").body(responseBody).build());
        }
    }

    private RestFederationModuleClient clientFor(Recorder rec) {
        return new RestFederationModuleClient(WebClient.builder().exchangeFunction(rec).build());
    }

    @Test
    void registerModule_postsAdminModulesWithFullBody() {
        Recorder rec = new Recorder();
        String slug = clientFor(rec).registerModule("owncast", "Owncast", "remote-shell",
                "https://cdn.acme.test/owncast/remoteEntry.json", "./routes", null, "internal",
                true, "{\"mountAt\":\"/owncast\"}").block();

        assertThat(slug).isEqualTo("owncast");
        assertThat(rec.requests).hasSize(1);
        Captured post = rec.requests.get(0);
        assertThat(post.method()).isEqualTo("POST");
        assertThat(post.path()).isEqualTo("/api/federation/admin/modules");
        // The exact upsert body the federation-api admin API expects.
        assertThat(post.body())
                .contains("\"slug\":\"owncast\"")
                .contains("\"displayName\":\"Owncast\"")
                .contains("\"kind\":\"remote-shell\"")
                .contains("\"remoteEntryUrl\":\"https://cdn.acme.test/owncast/remoteEntry.json\"")
                .contains("\"exposedModule\":\"./routes\"")
                .contains("\"visibility\":\"internal\"")
                .contains("\"enabled\":true")
                .contains("\"metadata\":\"{\\\"mountAt\\\":\\\"/owncast\\\"}\"");
    }

    @Test
    void registerModule_returnsSlugFromResponse() {
        Recorder rec = new Recorder();
        rec.responseBody = "{\"slug\":\"renamed\",\"id\":7}";
        String slug = clientFor(rec).registerModule("owncast", "Owncast", "remote-shell",
                "https://cdn.acme.test/x/remoteEntry.json", "./routes", null, "internal", true,
                "{}").block();
        assertThat(slug).isEqualTo("renamed");
    }

    @Test
    void unregisterModule_deletesBySlug_returnsTrue() {
        Recorder rec = new Recorder();
        Boolean ok = clientFor(rec).unregisterModule("owncast").block();

        assertThat(ok).isTrue();
        Captured del = rec.requests.get(0);
        assertThat(del.method()).isEqualTo("DELETE");
        assertThat(del.path()).isEqualTo("/api/federation/admin/modules/owncast");
    }

    @Test
    void unregisterModule_tolerates404_asIdempotentSuccess() {
        Recorder rec = new Recorder();
        rec.responseStatus = HttpStatus.NOT_FOUND;
        rec.responseBody = "{\"status\":404}";
        // A 404 = already absent = the desired end state; tolerated as success.
        assertThat(clientFor(rec).unregisterModule("gone").block()).isTrue();
    }

    @Test
    void unregisterModule_hardFailure_returnsFalseNotError() {
        Recorder rec = new Recorder();
        rec.responseStatus = HttpStatus.INTERNAL_SERVER_ERROR;
        rec.responseBody = "{\"status\":500}";
        // A real failure is surfaced as false (caller records + retries) rather than erroring.
        assertThat(clientFor(rec).unregisterModule("owncast").block()).isFalse();
    }

    @Test
    void noopClient_isNotReal_andMakesNoCall() {
        NoopFederationModuleClient noop = new NoopFederationModuleClient();
        assertThat(noop.isReal()).isFalse();
        assertThat(noop.registerModule("s", "d", "remote-shell", "u", "./routes", null, "internal",
                true, "{}").block()).isEqualTo("s");
        assertThat(noop.unregisterModule("s").block()).isTrue();
    }

    @Test
    void restClient_isReal() {
        assertThat(clientFor(new Recorder()).isReal()).isTrue();
    }
}
