package net.hugmesh.adminbff.inference;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.resilience4j.circuitbreaker.annotation.CircuitBreaker;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Reactive client for the on-prem GPU edge-AI inference server (the {@code edge_ai}
 * role's Ollama-style mesh API — see the edge-AI Jetson initiative). Single foundational
 * seam reused across the edge-AI features: infra/NIDS log triage (AIOps → Matrix
 * {@code @system} notifications), profile-image vision moderation, and the VN-character
 * sentiment/expression work.
 *
 * <p><b>Ships DARK</b> — {@code inference.edge-ai.enabled} defaults {@code false}, so a
 * cluster WITHOUT a GPU/edge-AI node boots clean and every call returns a
 * {@link TriageResult#disabled()} sentinel (the capability-gating contract: the UI/feature
 * degrades gracefully when no edge-AI node is present, mirroring the other optional
 * services). All inference is ON-PREM; no token/credential is sent and no cloud is called.
 *
 * <p><b>Fail-open, never fail-closed for a NOTIFY path:</b> a model error / timeout / open
 * circuit yields a {@code degraded} result rather than throwing, so a stalled edge-AI node
 * never blocks the caller's own work. (A MODERATION caller that must fail-closed should treat
 * {@code !available()} as "could not clear" — see the profile-image moderation hook.)
 *
 * <p>Boot-4 codec note: responses are read as {@code String} and parsed with a Jackson-2
 * {@link ObjectMapper} off the WebFlux codec path (the reactive codec is Jackson-3 / tools.jackson
 * and cannot decode into this Jackson-2 {@link JsonNode}), matching the established broker pattern.
 */
@Service
public class EdgeAiInferenceClient {

    private static final Logger log = LoggerFactory.getLogger(EdgeAiInferenceClient.class);
    private static final ObjectMapper MAPPER = new ObjectMapper();

    private final WebClient client;
    private final boolean enabled;
    private final String model;
    private final Duration timeout;

    @Autowired
    public EdgeAiInferenceClient(
            WebClient.Builder builder,
            @Value("${inference.edge-ai.enabled:false}") boolean enabled,
            @Value("${inference.edge-ai.base-url:http://edge-ai.hugmesh-backend.svc.cluster.local:11434}") String baseUrl,
            @Value("${inference.edge-ai.model:qwen2.5:0.5b}") String model,
            @Value("${inference.edge-ai.timeout-ms:30000}") long timeoutMs) {
        this.enabled = enabled;
        this.model = model;
        this.timeout = Duration.ofMillis(timeoutMs);
        this.client = enabled ? builder.clone().baseUrl(baseUrl).build() : null;
    }

    /** Constructor seam for tests: inject a pre-built WebClient (e.g. an ExchangeFunction stub). */
    EdgeAiInferenceClient(WebClient client, boolean enabled, String model, long timeoutMs) {
        this.client = client;
        this.enabled = enabled;
        this.model = model;
        this.timeout = Duration.ofMillis(timeoutMs);
    }

    /** True iff an edge-AI node is configured (the capability-gating flag). */
    public boolean isEnabled() {
        return enabled;
    }

    /**
     * Triage a batch of mesh infra / NIDS / file-integrity signals into a SOC-style verdict
     * (severity + one-line summary + recommended action). Disabled → {@link TriageResult#disabled()};
     * a model error / timeout / open circuit → {@link TriageResult#degraded(String)} (via the CB
     * fallback). The returned {@code summary} is the neutral note posted to admins.
     */
    @CircuitBreaker(name = "edge-ai", fallbackMethod = "triageFallback")
    public Mono<TriageResult> triageInfra(String signals) {
        if (!enabled || client == null) {
            return Mono.just(TriageResult.disabled());
        }
        String prompt = "You are an on-prem SOC analyst for a self-hosted mesh. Triage the following "
                + "infra / NIDS (Snort/Suricata) / file-integrity (AIDE) / k8s signals. Reply in exactly "
                + "three lines:\nSEVERITY: <low|medium|high|critical>\nSUMMARY: <one sentence>\n"
                + "ACTION: <the single most important action>\n\nSIGNALS:\n" + signals;
        return generate(prompt).map(EdgeAiInferenceClient::parseTriage);
    }

    /**
     * Low-level primitive: send a prompt to the model API ({@code POST /api/generate}, the
     * Ollama contract the edge_ai role serves) and return the generated text. Reused by the
     * higher-level helpers (triage, and — later — image-caption / sentiment for the VN work).
     */
    public Mono<String> generate(String prompt) {
        if (!enabled || client == null) {
            return Mono.just("");
        }
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("model", model);
        body.put("prompt", prompt);
        body.put("stream", false);
        return client.post().uri("/api/generate")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(body)
                .retrieve()
                .bodyToMono(String.class)
                .timeout(timeout)
                .map(EdgeAiInferenceClient::extractResponse);
    }

    @SuppressWarnings("unused") // resilience4j fallback (reactive signature: args + Throwable)
    private Mono<TriageResult> triageFallback(String signals, Throwable t) {
        log.warn("[edge-ai] triage unavailable, degrading: {}", t.toString());
        return Mono.just(TriageResult.degraded(t.getClass().getSimpleName()));
    }

    /** Pull the {@code response} text out of an Ollama {@code /api/generate} JSON body. */
    private static String extractResponse(String json) {
        try {
            JsonNode n = MAPPER.readTree(json);
            return n.path("response").asText("").trim();
        } catch (Exception e) {
            return "";
        }
    }

    /** Map free-text model output to a structured verdict (highest severity word wins). */
    static TriageResult parseTriage(String text) {
        if (text == null || text.isBlank()) {
            return TriageResult.degraded("empty-response");
        }
        String lower = text.toLowerCase();
        String severity = lower.contains("critical") ? "critical"
                : lower.contains("high") ? "high"
                : (lower.contains("medium") || lower.contains("moderate")) ? "medium"
                : lower.contains("low") ? "low"
                : "unknown";
        // Prefer an explicit "SUMMARY:" line for the neutral note; else the whole reply (capped).
        String summary = text;
        for (String line : text.split("\\r?\\n")) {
            if (line.toUpperCase().startsWith("SUMMARY:")) {
                summary = line.substring("SUMMARY:".length()).trim();
                break;
            }
        }
        if (summary.length() > 480) {
            summary = summary.substring(0, 480) + "…";
        }
        return new TriageResult(true, severity, summary, text);
    }
}
