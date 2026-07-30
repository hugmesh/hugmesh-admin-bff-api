package systems.hugmesh.adminbff.anubis;

import io.swagger.v3.oas.annotations.Operation;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Superadmin-only BFF surface for the Anubis proof-of-work challenge gate.
 *
 * <p>Anubis runs as its own {@code hugmesh-anubis} Deployment (an optional service,
 * default-off at the k8s level) in front of {@code hugmesh-fe-gateway} in the
 * {@code hugmesh-frontend} namespace — not a sidecar of this BFF or of the gateway.
 * It intercepts unauthenticated requests and issues a JavaScript PoW puzzle to filter
 * AI scrapers, credential-stuffers, and brute-force bots before they reach any upstream
 * service.
 *
 * <p>Exposes two SUPERADMIN-only endpoints:
 * <ul>
 *   <li>{@code GET /bff/admin/anubis/status} — whether Anubis is enabled + reachable
 *       from this BFF pod, plus the configured difficulty and management URL</li>
 *   <li>{@code GET /bff/admin/anubis/metrics} — Prometheus metrics proxied from the
 *       Anubis management port, parsed into a JSON list of {@code {name, labels, value}}
 *       entries alongside the raw text for direct display</li>
 * </ul>
 *
 * <p><b>Not enabled by default.</b> {@code app.anubis.enabled=false} (this BFF's own
 * default) makes both endpoints return a structured "not enabled" response rather than
 * attempting a connection — so a cluster with the Anubis optional service not deployed
 * does not get 503 cascades. The generator's admin-bff-api deployment manifest already
 * sets {@code ANUBIS_ENABLED=true} + the in-cluster {@code ANUBIS_MANAGEMENT_URL} when
 * the Anubis optional service is turned on for a brand.
 *
 * <p><b>Settings are read-only.</b> Anubis is configured entirely via environment
 * variables at its own pod startup (difficulty, target, bypass paths). Runtime mutation
 * requires a pod restart via the generator's ArgoCD deployment; there is no live
 * config API. The {@code difficulty} and {@code management-url} values this endpoint
 * reports come from THIS BFF's own config, not from Anubis itself, so they reflect
 * the deployment configuration rather than Anubis's runtime state.
 */
@RestController
@RequestMapping("/bff/admin/anubis")
public class AnubisController {

    private final AnubisClient client;

    @Value("${app.anubis.enabled:false}")
    private boolean enabled;

    @Value("${app.anubis.management-url:http://localhost:9090}")
    private String managementUrl;

    @Value("${app.anubis.difficulty:5}")
    private int difficulty;

    public AnubisController(AnubisClient client) {
        this.client = client;
    }

    /**
     * Returns Anubis configuration status visible to this BFF, plus a liveness probe
     * against the management endpoint. When {@code enabled=false} the health check is
     * skipped and {@code reachable} is always {@code false}.
     */
    @PreAuthorize("hasRole('SUPERADMIN')")
    @Operation(summary = "Status", operationId = "anubisStatus")
    @GetMapping("/status")
    public Mono<Map<String, Object>> status() {
        if (!enabled) {
            return Mono.just(notEnabled());
        }
        return client.health()
                .map(health -> {
                    Map<String, Object> r = new LinkedHashMap<>();
                    r.put("enabled", true);
                    r.put("managementUrl", managementUrl);
                    r.put("difficulty", difficulty);
                    r.put("health", health);
                    r.put("reachable", !"unreachable".equals(health));
                    return r;
                });
    }

    /**
     * Proxies the Prometheus metrics from the Anubis management port and parses them
     * into a JSON structure. The {@code raw} field contains the original Prometheus text;
     * {@code metrics} is a list of {@code {name, labels, value}} entries for display in
     * the admin UI metrics table.
     *
     * <p>When Anubis is not enabled or unreachable, returns
     * {@code {"enabled": false, "metrics": [], "raw": ""}}.
     */
    @PreAuthorize("hasRole('SUPERADMIN')")
    @Operation(summary = "Metrics", operationId = "anubisMetrics")
    @GetMapping("/metrics")
    public Mono<Map<String, Object>> metrics() {
        if (!enabled) {
            return Mono.just(Map.of("enabled", false, "metrics", List.of(), "raw", ""));
        }
        return client.metrics()
                .map(raw -> {
                    Map<String, Object> r = new LinkedHashMap<>();
                    r.put("enabled", true);
                    r.put("raw", raw);
                    r.put("metrics", parsePrometheus(raw));
                    return r;
                });
    }

    private Map<String, Object> notEnabled() {
        Map<String, Object> r = new LinkedHashMap<>();
        r.put("enabled", false);
        r.put("managementUrl", managementUrl);
        r.put("difficulty", difficulty);
        r.put("health", "not-enabled");
        r.put("reachable", false);
        return r;
    }

    /**
     * Parses Prometheus text-format metric lines (skipping comments and blank lines)
     * into a list of {@code {name, labels, value}} maps. Non-numeric values and
     * malformed lines are silently skipped — this is best-effort display data, not
     * a critical path.
     *
     * <p>Prometheus text format: {@code metric_name[{label="v",...}] value[ timestamp]}
     */
    static List<Map<String, Object>> parsePrometheus(String text) {
        List<Map<String, Object>> result = new ArrayList<>();
        if (text == null || text.isBlank()) return result;
        for (String line : text.split("\n")) {
            line = line.trim();
            if (line.isEmpty() || line.startsWith("#")) continue;
            String[] parts = line.split("\\s+", 3);
            if (parts.length < 2) continue;
            String namePart = parts[0];
            String rawValue = parts[1];
            double value;
            try {
                value = Double.parseDouble(rawValue);
            } catch (NumberFormatException e) {
                continue;
            }
            String name;
            String labels = null;
            int braceOpen = namePart.indexOf('{');
            if (braceOpen >= 0 && namePart.endsWith("}")) {
                name = namePart.substring(0, braceOpen);
                labels = namePart.substring(braceOpen + 1, namePart.length() - 1);
            } else {
                name = namePart;
            }
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("name", name);
            if (labels != null) m.put("labels", labels);
            m.put("value", value);
            result.add(m);
        }
        return result;
    }
}
