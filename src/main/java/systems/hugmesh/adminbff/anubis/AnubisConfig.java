package systems.hugmesh.adminbff.anubis;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.reactive.function.client.WebClient;

/**
 * Wires the reactive {@link WebClient} that the {@link AnubisController} uses to
 * reach the Anubis management endpoint.
 *
 * <p>Anubis runs as its own {@code hugmesh-anubis} Deployment (not a sidecar of this
 * BFF or of the gateway) in the {@code hugmesh-frontend} namespace, gated as an
 * optional service, and exposes a separate management port (default {@code :9090}) —
 * not the public challenge port {@code :8923}. The generator's admin-bff-api deployment
 * manifest already sets {@code ANUBIS_ENABLED=true} and points
 * {@code ANUBIS_MANAGEMENT_URL} at the in-cluster Anubis Service when the optional
 * service is deployed; this BFF's own default stays {@code false} so a cluster without
 * Anubis deployed still gets a clean "not enabled" response instead of a 503 cascade.
 *
 * <p>When {@code app.anubis.enabled=false} (default) no actual HTTP calls are issued
 * by the controller — a clear "not enabled" response is returned immediately. The
 * WebClient bean is still created (Spring cannot conditionally omit it when the
 * controller class is loaded); it is simply never called on the disabled path.
 */
@Configuration(proxyBeanMethods = false)
public class AnubisConfig {

    @Bean
    WebClient anubisWebClient(
            WebClient.Builder builder,
            @Value("${app.anubis.management-url:http://localhost:9090}") String managementUrl) {
        return builder.clone()
                .baseUrl(managementUrl != null ? managementUrl : "http://localhost:9090")
                .build();
    }

    @Bean
    AnubisClient anubisClient(WebClient anubisWebClient) {
        return new AnubisClient(anubisWebClient != null
                ? anubisWebClient : WebClient.builder().build());
    }
}
