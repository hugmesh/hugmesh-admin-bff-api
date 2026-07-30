package systems.hugmesh.adminbff.desktop;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

/**
 * The REAL {@link DesktopRegistryClient} — proxies the upstream Flatpak/OCI registry
 * (Flathub-OCI). Modeled on {@code RestArgoCdClient}: a reactive {@link WebClient} against
 * the configured upstream base URL. Wired ONLY when
 * {@code app.desktop.registry.enabled=true} ({@link DesktopRegistryConfig}); the
 * {@link NoopDesktopRegistryClient} is the ships-dark default.
 *
 * <p>This is the filtering reverse-proxy's UPSTREAM leg: the caller has already proven the
 * ref is in the requesting domain's ENABLED allowlist (the domain-lock + authz happen in
 * {@link DesktopRegistryService} BEFORE this is reached), so this only fetches the bytes for
 * an already-authorized ref. The exact upstream index path is validated against the deployed
 * OCI registry at integration time (the same "validate against the live server" caveat the
 * other REST clients carry).
 */
public class RestDesktopRegistryClient implements DesktopRegistryClient {

    private static final Logger log = LoggerFactory.getLogger(RestDesktopRegistryClient.class);

    private final WebClient http;

    public RestDesktopRegistryClient(String baseUrl, String authToken) {
        this(WebClient.builder()
                .baseUrl(baseUrl)
                .defaultHeader("Authorization", "Bearer " + (authToken == null ? "" : authToken))
                .build());
    }

    /** Test seam — inject a pre-built WebClient. */
    RestDesktopRegistryClient(WebClient http) {
        this.http = http;
    }

    @Override
    public Mono<String> fetchRefIndex(String appRef, String source) {
        return http.get()
                .uri(uri -> uri.path("/v2/{ref}/index").build(appRef))
                .retrieve()
                .bodyToMono(String.class)
                .doOnSuccess(r -> log.info("[desktop-registry] fetched upstream index for ref='{}' source={}",
                        appRef, source));
    }

    @Override
    public boolean isReal() {
        return true;
    }
}
