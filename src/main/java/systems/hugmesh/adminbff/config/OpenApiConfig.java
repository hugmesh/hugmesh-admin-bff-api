package systems.hugmesh.adminbff.config;

import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.servers.Server;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.List;

/**
 * Minimal OpenAPI document metadata for the admin BFF spec served by
 * springdoc-openapi-starter-webflux-ui at {@code /v3/api-docs}.
 *
 * <p>Sets a stable {@code info.title} (the service name) + {@code info.version} so
 * the generated artefacts downstream are sensibly named: the platform
 * ng-openapi-gen typed clients, the admin api-docs / SwaggerUI federated module,
 * and the docs pipeline all key off these fields. A programmatic {@link OpenAPI}
 * bean is used (rather than the {@code @OpenAPIDefinition} annotation) so the
 * metadata is plain bean wiring — no annotation reflection scan, which keeps the
 * GraalVM native build hint surface minimal.
 */
@Configuration(proxyBeanMethods = false)
public class OpenApiConfig {

    @Bean
    OpenAPI adminBffOpenApi() {
        return new OpenAPI()
                // Pin an empty-URL server so the dumped spec is DETERMINISTIC. Under Boot 4 /
                // springdoc 3.x the auto-generated "Generated server url" resolves to the live
                // request host:port — which is a RANDOM_PORT in the OpenApiSpecDumpTest, so the
                // committed spec would otherwise carry a per-run port (e.g. http://localhost:34851).
                // Boot 3.5 / springdoc 2.x emitted "" here; pin it to keep the byte-stable artefact.
                .servers(List.of(new Server().url("")))
                .info(new Info()
                        .title("hugmesh-admin-bff-api")
                        .version("0.1.0")
                        .description("Admin BFF API (/bff/**) — registration allowlist, "
                                + "namespace access, service-token brokering, and usage "
                                + "aggregation behind the backend gateway."));
    }
}
