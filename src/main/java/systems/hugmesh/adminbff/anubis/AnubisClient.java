package systems.hugmesh.adminbff.anubis;

import org.jspecify.annotations.NonNull;
import org.springframework.http.MediaType;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

/**
 * Reactive client for the Anubis management port.
 *
 * <p>Anubis exposes two management endpoints on its internal-only management port:
 * <ul>
 *   <li>{@code GET /healthz} — plain-text {@code ok} when Anubis is up</li>
 *   <li>{@code GET /metrics} — Prometheus text-format counters (challenges issued /
 *       passed / failed, blocked IPs, etc.)</li>
 * </ul>
 *
 * <p>Both calls are fire-and-forget timeouts; the controller wraps them with
 * {@code onErrorResume} so a non-reachable Anubis deployment produces a structured
 * "unreachable" response rather than a 503 cascade to the admin UI.
 */
public class AnubisClient {

    private final WebClient http;

    AnubisClient(@NonNull WebClient http) {
        this.http = http;
    }

    /** Returns raw Prometheus text from {@code /metrics}, or an empty string on error. */
    public Mono<String> metrics() {
        return http.get()
                .uri("/metrics")
                .accept(MediaType.TEXT_PLAIN)
                .retrieve()
                .bodyToMono(String.class)
                .onErrorResume(e -> Mono.just(""));
    }

    /** Returns raw health text from {@code /healthz}, or "unreachable" on error. */
    public Mono<String> health() {
        return http.get()
                .uri("/healthz")
                .retrieve()
                .bodyToMono(String.class)
                .onErrorResume(e -> Mono.just("unreachable"));
    }
}
