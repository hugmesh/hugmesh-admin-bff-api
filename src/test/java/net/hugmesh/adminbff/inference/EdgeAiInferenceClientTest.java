package net.hugmesh.adminbff.inference;

import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.web.reactive.function.client.ClientResponse;
import org.springframework.web.reactive.function.client.ExchangeFunction;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for the edge-AI inference client. Drives the REAL Boot-4 reactive codec via an
 * {@link ExchangeFunction} stub (the Ollama {@code /api/generate} contract), plus the
 * capability-gating (disabled) path and the free-text→verdict parser.
 */
class EdgeAiInferenceClientTest {

    private static EdgeAiInferenceClient enabledClientReturning(String body) {
        ExchangeFunction stub = req -> Mono.just(ClientResponse.create(HttpStatus.OK)
                .header("Content-Type", MediaType.APPLICATION_JSON_VALUE)
                .body(body)
                .build());
        WebClient wc = WebClient.builder().exchangeFunction(stub).build();
        return new EdgeAiInferenceClient(wc, true, "qwen2.5:0.5b", 5_000);
    }

    @Test
    void disabled_returnsSentinel_andNeverCallsTheModel() {
        // No WebClient at all — disabled must short-circuit before any HTTP.
        EdgeAiInferenceClient client = new EdgeAiInferenceClient((WebClient) null, false, "m", 5_000);
        assertThat(client.isEnabled()).isFalse();
        StepVerifier.create(client.triageInfra("[Snort] anything"))
                .assertNext(r -> {
                    assertThat(r.available()).isFalse();
                    assertThat(r.summary()).contains("not enabled");
                })
                .verifyComplete();
    }

    @Test
    void triageInfra_parsesModelVerdict_throughTheBoot4Codec() {
        EdgeAiInferenceClient client = enabledClientReturning(
                "{\"response\":\"SEVERITY: critical\\nSUMMARY: probable host compromise via tampered sshd\\nACTION: isolate the node\",\"done\":true}");
        StepVerifier.create(client.triageInfra("[AIDE] changed: /usr/sbin/sshd"))
                .assertNext(r -> {
                    assertThat(r.available()).isTrue();
                    assertThat(r.severity()).isEqualTo("critical");
                    assertThat(r.summary()).isEqualTo("probable host compromise via tampered sshd");
                    assertThat(r.isHighPriority()).isTrue();
                    assertThat(r.asNote()).startsWith("CRITICAL — ");
                })
                .verifyComplete();
    }

    @Test
    void triageInfra_emptyModelResponse_degrades() {
        EdgeAiInferenceClient client = enabledClientReturning("{\"response\":\"\"}");
        StepVerifier.create(client.triageInfra("noise"))
                .assertNext(r -> assertThat(r.available()).isFalse())
                .verifyComplete();
    }

    @Test
    void parseTriage_picksHighestSeverityWord_andFallsBackToFullTextSummary() {
        // No explicit SUMMARY: line → the whole (capped) reply becomes the note.
        TriageResult r = EdgeAiInferenceClient.parseTriage("This looks like a HIGH risk brute-force attempt.");
        assertThat(r.available()).isTrue();
        assertThat(r.severity()).isEqualTo("high");
        assertThat(r.summary()).contains("brute-force");

        // "critical" outranks "low" when both appear.
        assertThat(EdgeAiInferenceClient.parseTriage("low chatter but one CRITICAL implant").severity())
                .isEqualTo("critical");
        // No severity word → unknown, still available.
        assertThat(EdgeAiInferenceClient.parseTriage("nothing notable").severity()).isEqualTo("unknown");
    }
}
