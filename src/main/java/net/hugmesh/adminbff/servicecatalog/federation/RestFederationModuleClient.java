package net.hugmesh.adminbff.servicecatalog.federation;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.client.reactive.ReactorClientHttpConnector;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;
import reactor.netty.http.client.HttpClient;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * The REAL {@link FederationModuleClient} — talks to federation-api's admin API. Modeled on the
 * platform's reactive WebClient clients ({@link net.hugmesh.adminbff.argocd.RestArgoCdClient}):
 * a {@link WebClient} with a Bearer token on every call. Wired ONLY when
 * {@code app.appstore.federation.enabled=true} ({@link FederationModuleClientConfig}); the
 * {@link NoopFederationModuleClient} is the ships-dark default.
 *
 * <p>Two operations against federation-api's SUPERADMIN admin API (recon-pinned contract):
 * <ul>
 *   <li>{@code registerModule} → {@code POST /api/federation/admin/modules} with the module body
 *       (slug/displayName/kind/remoteEntryUrl/exposedModule/version/visibility/enabled/metadata).
 *       That endpoint is UPSERT-BY-SLUG, so a re-run updates the existing module rather than
 *       409ing (idempotent).</li>
 *   <li>{@code unregisterModule} → {@code DELETE /api/federation/admin/modules/{slug}} (soft-disable
 *       — federation-api never hard-deletes). A 404 (already absent) is tolerated as success.</li>
 * </ul>
 *
 * <p><b>Auth.</b> federation-api's {@code /api/federation/admin/modules} is gated
 * {@code hasRole('SUPERADMIN')} on the Casdoor JWT (no shared-secret / X-Internal-Token path
 * exists). So {@code auth-token} MUST be a Casdoor JWT carrying ROLE_SUPERADMIN (env-injected via
 * {@code app.appstore.federation.auth-token}, empty by default — never in git). The exact admin
 * body shape is validated against the deployed federation-api at integration time (the same
 * "validate against the live server" caveat the Casdoor/ArgoCD clients carry).
 */
public class RestFederationModuleClient implements FederationModuleClient {

    private static final Logger log = LoggerFactory.getLogger(RestFederationModuleClient.class);

    /** federation-api's SUPERADMIN module admin path. */
    static final String MODULES_PATH = "/api/federation/admin/modules";

    private final WebClient http;

    /**
     * Build the client on {@code httpClient} — in production the outbound client-mTLS connector
     * from {@link net.hugmesh.adminbff.config.OutboundMtlsClient} (decision 81a = A,
     * hugmesh-admin-bff-api#82): it presents this pod's keystore identity and trusts the cluster
     * CA, which federation-api's {@code client-auth=need} listener requires. A bare
     * {@code WebClient.builder()} here (JDK trust, no client certificate) dies at the TLS
     * handshake before the Bearer token is ever sent.
     */
    public RestFederationModuleClient(String baseUrl, String authToken, HttpClient httpClient) {
        this(WebClient.builder()
                .clientConnector(new ReactorClientHttpConnector(httpClient))
                .baseUrl(baseUrl)
                .defaultHeader("Authorization", "Bearer " + (authToken == null ? "" : authToken))
                .build());
    }

    /** Test seam — inject a pre-built WebClient (e.g. a stub ExchangeFunction). */
    RestFederationModuleClient(WebClient http) {
        this.http = http;
    }

    @Override
    public Mono<String> registerModule(String slug, String displayName, String kind, String remoteEntryUrl,
                                       String exposedModule, String version, String visibility,
                                       boolean enabled, String metadata) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("slug", slug);
        body.put("displayName", displayName);
        body.put("kind", kind);
        body.put("remoteEntryUrl", remoteEntryUrl);
        body.put("exposedModule", exposedModule);
        body.put("version", version);
        body.put("visibility", visibility);
        body.put("enabled", enabled);
        body.put("metadata", metadata);
        return http.post()
                .uri(MODULES_PATH)
                .bodyValue(body)
                .retrieve()
                .bodyToMono(Map.class)
                .map(resp -> {
                    Object registered = resp.get("slug");
                    return registered == null ? slug : registered.toString();
                })
                .doOnSuccess(s -> log.info("[federation] registered module slug={} kind={} visibility={}",
                        s, kind, visibility));
    }

    @Override
    public Mono<Boolean> unregisterModule(String slug) {
        return http.delete()
                .uri(MODULES_PATH + "/{slug}", slug)
                .retrieve()
                .toBodilessEntity()
                .doOnSuccess(r -> log.info("[federation] soft-disabled module slug={}", slug))
                .thenReturn(true)
                // 404 = already absent (federation-api DELETE 404s when the slug is unknown);
                // that IS the desired end state, so tolerate it as an idempotent success. Any
                // other failure returns false so the caller can record + retry.
                .onErrorResume(org.springframework.web.reactive.function.client.WebClientResponseException.NotFound.class,
                        e -> {
                            log.info("[federation] module slug={} already absent (404) — treating disable as done", slug);
                            return Mono.just(true);
                        })
                .onErrorResume(e -> {
                    log.warn("[federation] soft-disable module slug={} failed (will retry): {}", slug, e.toString());
                    return Mono.just(false);
                });
    }

    @Override
    public boolean isReal() {
        return true;
    }
}
