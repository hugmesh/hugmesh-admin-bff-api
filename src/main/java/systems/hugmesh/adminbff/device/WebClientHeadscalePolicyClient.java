package systems.hugmesh.adminbff.device;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

import java.time.Duration;
import java.util.Map;

/**
 * The REAL {@link HeadscalePolicyClient} — issues the CONFIRMED headscale gRPC-gateway policy
 * calls (Bearer API key) against {@code app.registry.headscale-acl.base-url}:
 * <pre>{@code
 *   GET /api/v1/policy            -> 200 {"policy":"<hujson>","updatedAt":"..."}
 *   PUT /api/v1/policy  {"policy":"<hujson>"}  -> 2xx (DB policy mode only)
 * }</pre>
 * (Confirmed against headscale's {@code hscontrol/api/v1/policy.go}: the body field is
 * {@code "policy"}; auth is {@code Authorization: Bearer <API_KEY>}; {@code setPolicy} is a
 * {@code PUT} and is rejected with 4xx when headscale is in file-policy mode rather than DB
 * mode — which the loop tolerates as a degraded keep-last-good.)
 *
 * <p>Wired ONLY when {@code app.registry.headscale-acl.enabled=true} (see
 * {@link HeadscaleAclConfig}); otherwise the {@link NoopHeadscalePolicyClient} stands in. The
 * client NEVER hard-fails — every call resolves to a {@link PushOutcome}/empty so the reconcile
 * loop keeps its last-good policy and retries next tick (fail-closed: a rejected or unreachable
 * headscale never widens / clears the live mesh ACL).
 */
public class WebClientHeadscalePolicyClient implements HeadscalePolicyClient {

    private static final Logger log = LoggerFactory.getLogger(WebClientHeadscalePolicyClient.class);

    static final String POLICY_PATH = "/api/v1/policy";

    private final WebClient http;
    private final String apiKey;
    private final Duration timeout;
    private final ObjectMapper mapper;

    public WebClientHeadscalePolicyClient(WebClient http, String apiKey, long timeoutMs, ObjectMapper mapper) {
        this.http = http;
        this.apiKey = apiKey;
        this.timeout = Duration.ofMillis(timeoutMs > 0 ? timeoutMs : 8000);
        this.mapper = mapper;
    }

    @Override
    public Mono<String> getPolicy() {
        // Read the envelope as a raw String and parse the `policy` field with the injected
        // ObjectMapper (the same parse seam HeadscaleNodesClient uses) — robust regardless of
        // the response codec, and the `policy` field is itself a JSON string we extract verbatim.
        return http.get()
                .uri(POLICY_PATH)
                .accept(MediaType.APPLICATION_JSON)
                .headers(this::applyAuth)
                .retrieve()
                .bodyToMono(String.class)
                .timeout(timeout)
                // fromCallable wraps JsonProcessingException as onError; .map→.flatMap
                .flatMap(envelope -> Mono.fromCallable(() -> extractPolicy(envelope)))
                .filter(s -> !s.isBlank())
                .onErrorResume(e -> {
                    // Unknown current policy (file-mode, never-set, unreachable, or unparseable body)
                    // -> empty, so the reconciler treats it as "must attempt a push" rather than
                    // erroring the tick.
                    log.debug("[headscale-acl] GET {} could not read current policy ({}) — treating as unknown",
                            POLICY_PATH, e.toString());
                    return Mono.empty();
                });
    }

    /** Pull the {@code policy} field out of the {@code {"policy":...,"updatedAt":...}} envelope.
     *  Empty on a missing/blank field; JsonProcessingException propagates as onError so the
     *  outer onErrorResume treats it as "unknown current" (same as unreachable host). */
    private String extractPolicy(String envelope) throws com.fasterxml.jackson.core.JsonProcessingException {
        if (envelope == null || envelope.isBlank()) return "";
        // JsonProcessingException propagates — Mono.fromCallable converts it to onError signal
        JsonNode p = mapper.readTree(envelope).get("policy");
        return (p == null || p.isNull()) ? "" : p.asText();
    }

    @Override
    public Mono<PushOutcome> setPolicy(String policyJson) {
        if (policyJson == null || policyJson.isBlank()) {
            // Defensive: never PUT an empty body (would clear the live policy). Fail-closed.
            return Mono.just(PushOutcome.degraded("refused empty policy body"));
        }
        return http.put()
                .uri(POLICY_PATH)
                .contentType(MediaType.APPLICATION_JSON)
                .headers(this::applyAuth)
                .bodyValue(Map.of("policy", policyJson))
                .retrieve()
                .toBodilessEntity()
                .timeout(timeout)
                .thenReturn(PushOutcome.applied())
                .doOnSuccess(o -> log.info("[headscale-acl] PUT {} applied ({} bytes)",
                        POLICY_PATH, policyJson.length()))
                .onErrorResume(e -> {
                    log.warn("[headscale-acl] PUT {} degraded — keeping last-good, retry next tick: {}",
                            POLICY_PATH, e.toString());
                    return Mono.just(PushOutcome.degraded(e.toString()));
                });
    }

    @Override
    public boolean isReal() {
        return true;
    }

    /** Add the Bearer API key iff configured (placeholder-only; never inline). */
    private void applyAuth(HttpHeaders h) {
        if (apiKey != null && !apiKey.isBlank()) {
            h.setBearerAuth(apiKey);
        }
    }
}
