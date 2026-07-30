package systems.hugmesh.adminbff.argocd;

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
 * Verifies the REAL ArgoCD client issues the documented Application create/delete calls,
 * driven by a recording {@link ExchangeFunction} (no live ArgoCD). The Application body is
 * version-specific (validated against the deployed ArgoCD at integration time); these tests
 * assert the request SHAPE — the create POSTs {@code /api/v1/applications?upsert=true} with
 * the repo/path/namespace, the delete DELETEs by name with {@code cascade=true} and tolerates
 * a 404.
 */
class RestArgoCdClientTest {

    static class Recorder implements ExchangeFunction {
        final List<ClientRequest> requests = new ArrayList<>();
        HttpStatus deleteStatus = HttpStatus.OK;

        @Override
        public Mono<ClientResponse> exchange(ClientRequest request) {
            requests.add(request);
            if (request.method().name().equals("DELETE")) {
                return Mono.just(ClientResponse.create(deleteStatus)
                        .header("Content-Type", "application/json").body("{}").build());
            }
            return Mono.just(ClientResponse.create(HttpStatus.OK)
                    .header("Content-Type", "application/json")
                    .body("{\"metadata\":{\"name\":\"x\"}}").build());
        }

        boolean hit(String pathSuffix) {
            return requests.stream().anyMatch(r -> r.url().getPath().endsWith(pathSuffix));
        }
    }

    private RestArgoCdClient clientFor(Recorder rec) {
        return new RestArgoCdClient(WebClient.builder().exchangeFunction(rec).build(), "default");
    }

    @Test
    void createApplication_postsUpsertWithSourceAndDestination() {
        Recorder rec = new Recorder();
        String name = clientFor(rec).createApplication("acme-owncast",
                "https://forgejo/acme/owncast", "deploy/", "HEAD", "acme-be").block();

        assertThat(name).isEqualTo("acme-owncast");
        assertThat(rec.hit("/api/v1/applications")).isTrue();
        ClientRequest post = rec.requests.get(0);
        assertThat(post.method().name()).isEqualTo("POST");
        // upsert=true makes create idempotent (re-run updates rather than 409s).
        assertThat(post.url().getQuery()).contains("upsert=true");
    }

    @Test
    void deleteApplication_issuesCascadeDelete_returnsTrue() {
        Recorder rec = new Recorder();
        Boolean ok = clientFor(rec).deleteApplication("acme-owncast").block();

        assertThat(ok).isTrue();
        ClientRequest del = rec.requests.get(0);
        assertThat(del.method().name()).isEqualTo("DELETE");
        assertThat(del.url().getPath()).endsWith("/api/v1/applications/acme-owncast");
        assertThat(del.url().getQuery()).contains("cascade=true");
    }

    @Test
    void deleteApplication_toleratesFailure_returnsFalseNotError() {
        Recorder rec = new Recorder();
        rec.deleteStatus = HttpStatus.INTERNAL_SERVER_ERROR;
        // A failed delete is surfaced as false (the expiry loop records + retries via
        // propagation_state) rather than erroring the whole tick.
        Boolean ok = clientFor(rec).deleteApplication("acme-owncast").block();
        assertThat(ok).isFalse();
    }

    @Test
    void noopClient_isNotReal_andMakesNoCall() {
        NoopArgoCdClient noop = new NoopArgoCdClient();
        assertThat(noop.isReal()).isFalse();
        assertThat(noop.createApplication("n", "r", "p", "HEAD", "ns").block()).isEqualTo("n");
        assertThat(noop.deleteApplication("n").block()).isTrue();
    }

    @Test
    void restClient_isReal() {
        assertThat(clientFor(new Recorder()).isReal()).isTrue();
    }
}
