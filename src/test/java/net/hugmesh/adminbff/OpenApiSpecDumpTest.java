package net.hugmesh.adminbff;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.config.ConfigurableListableBeanFactory;
import org.springframework.beans.factory.support.BeanDefinitionRegistry;
import org.springframework.beans.factory.support.BeanDefinitionRegistryPostProcessor;
import org.springframework.boot.webtestclient.autoconfigure.AutoConfigureWebTestClient;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.reactive.server.WebTestClient;
import net.hugmesh.adminbff.support.AdminBffPostgresTestSupport;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * DETERMINISTIC OpenAPI SPEC DUMP — the CI-friendly replacement for curling a
 * manually-run server. This boots the full admin-BFF application context under the
 * {@code test} profile (where {@code /v3/api-docs} is PUBLIC — see
 * {@link net.hugmesh.adminbff.config.SecurityConfig#devFilterChain}), GETs the
 * springdoc-generated OpenAPI 3 document, normalizes it to a STABLE byte form
 * (alphabetically-sorted keys + 2-space pretty print + trailing newline), and writes it
 * to a committed path.
 *
 * <p><b>Why a test, not a server:</b> the spec is produced as an ordinary build artefact
 * during {@code ./mvnw test} — no port to bind, no token, no running BFF, no curl. The
 * platform ng-openapi-gen typed client consumes the COMMITTED copy of this file; the docs
 * pipeline reads the same artefact.
 *
 * <p><b>Determinism:</b> springdoc emits keys in a non-deterministic order across
 * runs/JVMs, which would produce noisy diffs. {@link SerializationFeature#ORDER_MAP_ENTRIES_BY_KEYS}
 * re-serializes every object with sorted keys, so re-running the dump on an UNCHANGED API
 * yields a byte-identical file (idempotent). A change to any endpoint/DTO is the ONLY
 * thing that moves the file — exactly the review signal we want.
 *
 * <p><b>Drift guard (optional):</b> the {@code -Dopenapi.spec.check=true} flag flips this
 * from "write" to "assert the committed file already matches" — wire that into a CI verify
 * lane to fail a build whose committed spec is stale. Default (no flag) is write-and-pass
 * so a developer just re-runs the test to refresh the spec.
 *
 * <p>Uses the same {@code test} profile + {@link AdminBffPostgresTestSupport} Testcontainers
 * Postgres schema and a mocked {@link ReactiveJwtDecoder} (no live Casdoor issuer is
 * contacted) as the repo's other full-context tests.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
// springdoc renders the full ~170-path document lazily on the first /v3/api-docs hit,
// which can exceed the WebTestClient 5s default blocking-read timeout on a cold context.
// Give the spec fetch a generous timeout so the dump is robust (not flaky) in CI.
@AutoConfigureWebTestClient(timeout = "PT60S")
@ActiveProfiles("test")
@Import(OpenApiSpecDumpTest.ExcludeTestProbeControllers.class)
class OpenApiSpecDumpTest extends AdminBffPostgresTestSupport {

    /**
     * The full-context boot scans the whole {@code net.hugmesh.adminbff} package,
     * which sweeps in three TOP-LEVEL package-private {@code @RestController} probe stand-ins
     * that live in test sources under {@code net.hugmesh.adminbff.config}
     * ({@code Probes} in {@code SecurityConfigPathRulesTest}, {@code Guarded} in
     * {@code MethodSecuritySuperadminBypassTest}, {@code InternalProbes} in
     * {@code InternalSurfaceRoleMatrixTest}). Because they are top-level (not nested)
     * they get registered as beans. This {@link ImportBeanDefinitionRegistrar} removes those
     * test-only bean definitions before the handler mapping is built, leaving the real
     * production surface — the only thing the dumped spec should describe — untouched.
     *
     * <p>They leak in TWO different ways, and only the first one is self-announcing:
     * <ul>
     *   <li>{@code Probes} / {@code Guarded} COLLIDE with real controllers (e.g.
     *       {@code Probes#admin()} vs {@code AdminController#allowlist()}, both mapping
     *       {@code GET /bff/admin/allowlist}) and fail the handler-mapping init with an
     *       "Ambiguous mapping" — a loud boot failure.</li>
     *   <li>{@code InternalProbes} maps the catch-all {@code /bff/internal/**}, which
     *       collides with nothing (Spring prefers the more specific real patterns), so the
     *       context boots CLEANLY and the probe is silently dumped into the committed spec
     *       as a fake {@code /bff/internal/**} path with seven {@code any*} operations.
     *       That is the dangerous shape: nothing fails, the spec just quietly grows a
     *       public-looking endpoint that does not exist in production. It must stay in this
     *       set even though omitting it breaks no test.</li>
     * </ul>
     */
    static class ExcludeTestProbeControllers implements BeanDefinitionRegistryPostProcessor {
        private static final Set<String> TEST_PROBE_TYPES = Set.of(
                "net.hugmesh.adminbff.config.Probes",
                "net.hugmesh.adminbff.config.Guarded",
                "net.hugmesh.adminbff.config.InternalProbes");

        @Override
        public void postProcessBeanDefinitionRegistry(BeanDefinitionRegistry registry) {
            // Runs AFTER component scanning has registered every bean definition, so the
            // scanned probe controllers are present and can be removed before the
            // RequestMappingHandlerMapping is built.
            for (String name : registry.getBeanDefinitionNames()) {
                String beanClass = registry.getBeanDefinition(name).getBeanClassName();
                if (beanClass != null && TEST_PROBE_TYPES.contains(beanClass)) {
                    registry.removeBeanDefinition(name);
                }
            }
        }

        @Override
        public void postProcessBeanFactory(ConfigurableListableBeanFactory beanFactory) {
            // no-op
        }
    }

    /** Committed spec path (repo-relative; the test runs with cwd = module root). */
    private static final Path SPEC_PATH = Path.of("src", "main", "resources", "openapi", "openapi.json");

    private static final ObjectMapper STABLE_MAPPER = new ObjectMapper()
            .enable(SerializationFeature.ORDER_MAP_ENTRIES_BY_KEYS)
            .enable(SerializationFeature.INDENT_OUTPUT);

    @Autowired WebTestClient client;

    /** No live Casdoor issuer in CI — mock the reactive JWT decoder so the oauth2
     *  resource-server wiring is satisfied without a network call. */
    @MockitoBean ReactiveJwtDecoder reactiveJwtDecoder;

    @Test
    void dumpsDeterministicOpenApiSpec() throws Exception {
        // The Accept: application/json header is REQUIRED. springdoc-webflux's
        // openApiResource only renders the spec for the JSON media type; a default
        // (*/*) Accept falls through to an empty `{}` text/plain body.
        String raw = client.get().uri("/v3/api-docs")
                .accept(MediaType.APPLICATION_JSON)
                .exchange()
                .expectStatus().isOk()
                .expectBody(String.class)
                .returnResult()
                .getResponseBody();

        assertThat(raw).as("springdoc must serve a non-empty /v3/api-docs").isNotBlank();

        // Re-serialize with sorted keys + indentation so the on-disk form is stable
        // across runs/JVMs (springdoc's own key order is not guaranteed).
        JsonNode tree = STABLE_MAPPER.readTree(raw);
        String stable = STABLE_MAPPER.writeValueAsString(tree) + "\n";

        // Sanity: the document must describe the admin-BFF surface, not an empty shell.
        assertThat(tree.path("openapi").asText()).startsWith("3.");
        assertThat(tree.path("paths").fieldNames())
                .toIterable()
                .as("the admin BFF surface must be present in the dumped spec")
                .anyMatch(p -> p.startsWith("/bff/"));

        boolean checkOnly = Boolean.getBoolean("openapi.spec.check");
        if (checkOnly) {
            assertThat(Files.exists(SPEC_PATH))
                    .as("committed spec %s must exist when -Dopenapi.spec.check=true", SPEC_PATH)
                    .isTrue();
            String committed = Files.readString(SPEC_PATH, StandardCharsets.UTF_8);
            assertThat(committed)
                    .as("committed %s is STALE — re-run `./mvnw -Dtest=OpenApiSpecDumpTest test` "
                            + "(without -Dopenapi.spec.check) and commit the refreshed spec", SPEC_PATH)
                    .isEqualTo(stable);
            return;
        }

        Files.createDirectories(SPEC_PATH.getParent());
        Files.writeString(SPEC_PATH, stable, StandardCharsets.UTF_8);
    }
}
