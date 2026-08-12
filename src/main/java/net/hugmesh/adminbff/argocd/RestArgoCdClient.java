package net.hugmesh.adminbff.argocd;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * The REAL {@link ArgoCdClient} — talks to the ArgoCD API server. Modeled on the platform's
 * reactive WebClient clients ({@code CasdoorAdminClient}): a {@link WebClient} with a Bearer
 * token on every call. Wired ONLY when {@code app.appstore.effector.enabled=true}
 * ({@link ArgoCdConfig}); the {@link NoopArgoCdClient} is the ships-dark default.
 *
 * <p>Two operations, mapping to the documented ArgoCD REST API (v2.x):
 * <ul>
 *   <li>{@code createApplication} → {@code POST /api/v1/applications?upsert=true} with the
 *       Application body (source repo/path/targetRevision + destination namespace, an
 *       automated selfHeal+prune syncPolicy). {@code upsert=true} makes the create
 *       idempotent — a re-run updates the existing Application rather than 409ing.</li>
 *   <li>{@code deleteApplication} → {@code DELETE /api/v1/applications/{name}?cascade=true}.
 *       A 404 (already gone) is tolerated as success — teardown is idempotent.</li>
 * </ul>
 *
 * <p>The Application's <i>manifests</i> are synced from Git by ArgoCD (selfHeal is law);
 * this client only creates/deletes the one {@code Application} resource that registers the
 * repo with ArgoCD. The exact body shape is validated against the deployed ArgoCD version
 * at integration time (the same "validate against the live server" caveat the Casdoor
 * client carries); this implements the documented v2.x shape.
 */
public class RestArgoCdClient implements ArgoCdClient {

    private static final Logger log = LoggerFactory.getLogger(RestArgoCdClient.class);

    private final WebClient http;
    private final String project;

    public RestArgoCdClient(String baseUrl, String authToken, String project) {
        this(WebClient.builder()
                        .baseUrl(baseUrl)
                        .defaultHeader("Authorization", "Bearer " + (authToken == null ? "" : authToken))
                        .build(),
                project);
    }

    /** Test seam — inject a pre-built WebClient (e.g. a stub ExchangeFunction). */
    RestArgoCdClient(WebClient http, String project) {
        this.http = http;
        this.project = project == null || project.isBlank() ? "default" : project;
    }

    @Override
    public Mono<String> createApplication(String name, String repoUrl, String path,
                                          String targetRevision, String destNamespace) {
        Map<String, Object> body = applicationBody(name, repoUrl, path, targetRevision, destNamespace);
        return http.post()
                .uri(uri -> uri.path("/api/v1/applications").queryParam("upsert", "true").build())
                .bodyValue(body)
                .retrieve()
                .bodyToMono(Map.class)
                .doOnSuccess(r -> log.info("[argocd] created/updated Application '{}' (repo={} ns={})",
                        name, repoUrl, destNamespace))
                .thenReturn(name);
    }

    @Override
    public Mono<Boolean> deleteApplication(String name) {
        return http.delete()
                .uri(uri -> uri.path("/api/v1/applications/{name}")
                        .queryParam("cascade", "true").build(name))
                .retrieve()
                .bodyToMono(Map.class)
                .doOnSuccess(r -> log.info("[argocd] deleted Application '{}'", name))
                .thenReturn(true)
                // 404 = already gone; teardown is idempotent. Any other error is a real
                // failure the caller should retry (returns false rather than erroring out
                // so the expiry loop's propagation_state can record + retry next tick).
                .onErrorResume(e -> {
                    log.warn("[argocd] delete Application '{}' failed (will retry): {}", name, e.toString());
                    return Mono.just(false);
                });
    }

    @Override
    public boolean isReal() {
        return true;
    }

    /** The ArgoCD {@code Application} body: source (repo/path/rev) + destination
     *  (in-cluster, the per-domain namespace) + an automated self-heal+prune syncPolicy. */
    private Map<String, Object> applicationBody(String name, String repoUrl, String path,
                                                String targetRevision, String destNamespace) {
        Map<String, Object> source = new LinkedHashMap<>();
        source.put("repoURL", repoUrl);
        source.put("path", path == null || path.isBlank() ? "." : path);
        source.put("targetRevision", targetRevision == null || targetRevision.isBlank()
                ? "HEAD" : targetRevision);

        Map<String, Object> destination = new LinkedHashMap<>();
        destination.put("server", "https://kubernetes.default.svc");
        destination.put("namespace", destNamespace);

        Map<String, Object> automated = new LinkedHashMap<>();
        automated.put("prune", true);
        automated.put("selfHeal", true);
        Map<String, Object> syncPolicy = new LinkedHashMap<>();
        syncPolicy.put("automated", automated);
        syncPolicy.put("syncOptions", java.util.List.of("CreateNamespace=false"));

        Map<String, Object> spec = new LinkedHashMap<>();
        spec.put("project", project);
        spec.put("source", source);
        spec.put("destination", destination);
        spec.put("syncPolicy", syncPolicy);

        Map<String, Object> metadata = new LinkedHashMap<>();
        metadata.put("name", name);

        Map<String, Object> application = new LinkedHashMap<>();
        application.put("metadata", metadata);
        application.put("spec", spec);
        return application;
    }
}
