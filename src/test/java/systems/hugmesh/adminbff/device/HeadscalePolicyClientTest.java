package systems.hugmesh.adminbff.device;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.web.reactive.function.client.ClientRequest;
import org.springframework.web.reactive.function.client.ClientResponse;
import org.springframework.web.reactive.function.client.ExchangeFunction;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;
import systems.hugmesh.adminbff.device.HeadscalePolicyClient.PushOutcome;

import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The headscale policy WRITE client, proven against the CONFIRMED headscale gRPC-gateway shape
 * with a recording {@link ExchangeFunction} (no live headscale — same seam the
 * {@code AnnouncementMastodonClient} tests use):
 * <ul>
 *   <li>{@code setPolicy} issues {@code PUT /api/v1/policy} with body {@code {"policy":...}} and
 *       the Bearer API key, returning {@link PushOutcome#applied} on 2xx;</li>
 *   <li>{@code getPolicy} issues {@code GET /api/v1/policy} and extracts the {@code policy} field;</li>
 *   <li>a non-2xx PUT is SWALLOWED to {@link PushOutcome#degraded} (fail-closed keep-last-good),
 *       NEVER an error signal;</li>
 *   <li>an empty/blank policy body is REFUSED (never PUT an empty body that would clear the
 *       live policy);</li>
 *   <li>the Noop client issues ZERO HTTP and reports {@link PushOutcome#stubbed}.</li>
 * </ul>
 */
class HeadscalePolicyClientTest {

    /** Records outgoing requests and returns a canned headscale policy response. */
    static class Recorder implements ExchangeFunction {
        private static final ObjectMapper MAPPER = new ObjectMapper();
        final List<ClientRequest> requests = new ArrayList<>();
        HttpStatus putStatus = HttpStatus.OK;
        String getPolicyValue = "{\"acls\":[]}";

        @Override
        public Mono<ClientResponse> exchange(ClientRequest request) {
            requests.add(request);
            if (request.method().name().equals("GET")) {
                // Build the JSON envelope with Jackson so the embedded policy string is
                // correctly escaped regardless of its contents (no hand-rolled escaping).
                String body = json(MAPPER.createObjectNode()
                        .put("policy", getPolicyValue)
                        .put("updatedAt", "2026-06-22T00:00:00Z"));
                return Mono.just(ClientResponse.create(HttpStatus.OK)
                        .header("Content-Type", "application/json")
                        .body(body)
                        .build());
            }
            // PUT
            return Mono.just(ClientResponse.create(putStatus)
                    .header("Content-Type", "application/json")
                    .body(putStatus.is2xxSuccessful()
                            ? "{\"policy\":\"x\",\"updatedAt\":\"2026-06-22T00:00:00Z\"}"
                            : "{\"message\":\"policy is read-only in file mode\"}")
                    .build());
        }

        private static String json(com.fasterxml.jackson.databind.JsonNode n) {
            try {
                return MAPPER.writeValueAsString(n);
            } catch (Exception e) {
                throw new IllegalStateException(e);
            }
        }
    }

    private static WebClientHeadscalePolicyClient client(Recorder rec, String apiKey) {
        WebClient web = WebClient.builder()
                .baseUrl("http://headscale.invalid")
                .exchangeFunction(rec)
                .build();
        return new WebClientHeadscalePolicyClient(web, apiKey, 8000, new ObjectMapper());
    }

    @Test
    void setPolicy_putsRealPolicy_withBearer_returnsApplied() {
        Recorder rec = new Recorder();
        PushOutcome outcome = client(rec, "vault-injected-key")
                .setPolicy("{\"ssh\":[]}").block();

        assertThat(outcome.isApplied()).isTrue();
        assertThat(rec.requests).hasSize(1);
        ClientRequest put = rec.requests.get(0);
        assertThat(put.method().name()).isEqualTo("PUT");
        assertThat(put.url().getPath()).isEqualTo("/api/v1/policy");
        assertThat(put.headers().getFirst("Authorization")).isEqualTo("Bearer vault-injected-key");
    }

    @Test
    void setPolicy_noApiKey_sendsNoAuthHeader_butStillPuts() {
        Recorder rec = new Recorder();
        PushOutcome outcome = client(rec, "").setPolicy("{\"ssh\":[]}").block();
        assertThat(outcome.isApplied()).isTrue();
        assertThat(rec.requests.get(0).headers().getFirst("Authorization")).isNull();
    }

    @Test
    void setPolicy_nonProcessable_isSwallowedToDegraded_keepLastGood() {
        Recorder rec = new Recorder();
        rec.putStatus = HttpStatus.BAD_REQUEST;   // e.g. headscale in file-policy mode
        StepVerifier.create(client(rec, "k").setPolicy("{\"ssh\":[]}"))
                .assertNext(o -> {
                    assertThat(o.isDegraded()).isTrue();   // NOT an error signal
                    assertThat(o.isApplied()).isFalse();
                })
                .verifyComplete();
    }

    @Test
    void setPolicy_emptyBody_isRefused_neverPuts() {
        Recorder rec = new Recorder();
        PushOutcome outcome = client(rec, "k").setPolicy("   ").block();
        assertThat(outcome.isDegraded()).isTrue();
        assertThat(rec.requests).isEmpty();   // never PUT an empty body that would clear policy
    }

    @Test
    void getPolicy_getsAndExtractsPolicyField() {
        Recorder rec = new Recorder();
        rec.getPolicyValue = "{\"ssh\":[{\"action\":\"accept\"}]}";
        String policy = client(rec, "k").getPolicy().block();

        assertThat(rec.requests).hasSize(1);
        assertThat(rec.requests.get(0).method().name()).isEqualTo("GET");
        assertThat(rec.requests.get(0).url().getPath()).isEqualTo("/api/v1/policy");
        assertThat(policy).isEqualTo("{\"ssh\":[{\"action\":\"accept\"}]}");
    }

    @Test
    void getPolicy_blankPolicy_isEmptyMono() {
        Recorder rec = new Recorder();
        rec.getPolicyValue = "";   // headscale has no policy yet / file mode
        StepVerifier.create(client(rec, "k").getPolicy())
                .verifyComplete();   // empty -> "unknown current", reconciler will attempt a push
    }

    @Test
    void isReal_distinguishesTheTwoImpls() {
        Recorder rec = new Recorder();
        assertThat(client(rec, "k").isReal()).isTrue();
        assertThat(new NoopHeadscalePolicyClient().isReal()).isFalse();
    }

    @Test
    void noopClient_issuesNoHttp_andStubs() {
        NoopHeadscalePolicyClient noop = new NoopHeadscalePolicyClient();
        StepVerifier.create(noop.setPolicy("{\"ssh\":[]}"))
                .assertNext(o -> assertThat(o.isStubbed()).isTrue())
                .verifyComplete();
        StepVerifier.create(noop.getPolicy()).verifyComplete();   // disabled knows no live policy
    }
}
