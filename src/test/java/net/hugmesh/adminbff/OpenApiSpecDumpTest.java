package net.hugmesh.adminbff;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.webtestclient.autoconfigure.AutoConfigureWebTestClient;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.springframework.web.reactive.result.condition.PatternsRequestCondition;
import org.springframework.web.reactive.result.method.RequestMappingInfo;
import org.springframework.web.reactive.result.method.annotation.RequestMappingHandlerMapping;
import net.hugmesh.adminbff.support.AdminBffPostgresTestSupport;
import net.hugmesh.adminbff.support.ExcludeTestSourcedControllers;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;

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
// The full-context boot scans all of net.hugmesh.adminbff, and that scan reaches
// target/test-classes — sweeping in the TOP-LEVEL package-private @RestController probe
// stand-ins declared alongside the config slice tests. ExcludeTestSourcedControllers withdraws
// them by CODE SOURCE rather than by name; the predecessor hardcoded three class names here, and
// the third (InternalProbes) had to be added by hand AFTER its /bff/internal/** catch-all had
// already leaked a 114-line phantom path into the committed spec below on every `./mvnw test`.
// specDescribesOnlyMainSourcedHandlers() is the standing, name-free proof that it is complete.
@Import(ExcludeTestSourcedControllers.class)
class OpenApiSpecDumpTest extends AdminBffPostgresTestSupport {

    /** Committed spec path (repo-relative; the test runs with cwd = module root). */
    private static final Path SPEC_PATH = Path.of("src", "main", "resources", "openapi", "openapi.json");

    private static final ObjectMapper STABLE_MAPPER = new ObjectMapper()
            .enable(SerializationFeature.ORDER_MAP_ENTRIES_BY_KEYS)
            .enable(SerializationFeature.INDENT_OUTPUT);

    @Autowired WebTestClient client;

    /**
     * The live routing table springdoc renders the document from — the source of truth both
     * guards below are derived from. Qualified by bean name because a WebFlux context can expose
     * more than one {@code HandlerMapping}; the annotated {@code @Controller} surface springdoc
     * documents is the one under {@code requestMappingHandlerMapping}.
     */
    @Autowired @Qualifier("requestMappingHandlerMapping") RequestMappingHandlerMapping handlerMapping;

    /** No live Casdoor issuer in CI — mock the reactive JWT decoder so the oauth2
     *  resource-server wiring is satisfied without a network call. */
    @MockitoBean ReactiveJwtDecoder reactiveJwtDecoder;

    @Test
    void dumpsDeterministicOpenApiSpec() throws Exception {
        JsonNode tree = fetchSpec();

        // Re-serialize with sorted keys + indentation so the on-disk form is stable
        // across runs/JVMs (springdoc's own key order is not guaranteed).
        String stable = STABLE_MAPPER.writeValueAsString(tree) + "\n";

        // Sanity: the document must describe the admin-BFF surface, not an empty shell.
        assertThat(tree.path("openapi").asText()).startsWith("3.");
        assertThat(tree.path("paths").fieldNames())
                .toIterable()
                .as("the admin BFF surface must be present in the dumped spec")
                .anyMatch(p -> p.startsWith("/bff/"));

        // GATE THE WRITE. Everything below persists this document to a file the ng-openapi-gen
        // typed clients and the docs pipeline treat as the contract, so BOTH pollution checks run
        // first and a tainted document never reaches disk — a failure leaves the working tree
        // clean instead of handing the developer a dirty spec to puzzle over. Both are needed:
        // the routing-table check alone cannot see a phantom path with no handler behind it, and
        // the path check alone cannot see a probe that adds an OPERATION to a path a real
        // controller already publishes (same key, extra verb — the document grows, the path set
        // does not).
        assertNoTestSourcedHandlers();
        assertOnlyMainSourcedPaths(tree);

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

    /**
     * THE ANTI-STALENESS HALF of the probe-exclusion fix, stated against the CONTEXT rather than
     * the document.
     *
     * <p>{@link ExcludeTestSourcedControllers} decides what to withdraw; this decides whether the
     * withdrawal was complete, and it does so without naming a single probe — so it stays honest
     * as the test sources grow. The guard it replaces was a hand-maintained class-name list that
     * agreed with itself: when a third top-level probe appeared, the exclusion missed it, this test
     * still went GREEN, and every {@code ./mvnw test} rewrote the committed contract with a phantom
     * {@code /bff/internal/**} path carrying seven operations. Nothing was ever red. That is the
     * failure mode these two assertions exist to make impossible.
     *
     * <p>This one catches a leaked probe even when it does NOT change the set of documented paths
     * — e.g. a probe answering a different HTTP method on a path a real controller already
     * publishes. That is neither an "Ambiguous mapping" boot failure nor a new spec path, so
     * {@link #assertOnlyMainSourcedPaths} cannot see it; only the routing table can.
     *
     * <p>Note on what a mutation can prove here: {@code dumpsDeterministicOpenApiSpec()} calls
     * {@code assertNoTestSourcedHandlers()} immediately before {@code assertOnlyMainSourcedPaths()}
     * in the SAME method, so a leaked probe throws in the first and the second never executes. The
     * two guards are complementary in WHAT they can detect, but they are not independently
     * exercised by one mutation, and no mutation that trips this one can also demonstrate the
     * other. Proving the path check requires a separate mutation that neuters this one first.
     */
    @Test
    void specDescribesOnlyMainSourcedHandlers() {
        assertNoTestSourcedHandlers();
    }

    private void assertNoTestSourcedHandlers() {
        // Offending handler class -> the patterns it would publish, so a failure names the file
        // to fix rather than merely asserting a size.
        TreeMap<String, TreeSet<String>> testSourcedHandlers = new TreeMap<>();
        handlerMapping.getHandlerMethods().forEach((info, method) -> {
            // getBeanType() is already the user class (HandlerMethod unwraps CGLIB proxies), so
            // the code-source probe sees the class javac emitted, not a generated subclass.
            if (ExcludeTestSourcedControllers.isTestSourced(method.getBeanType())) {
                testSourcedHandlers
                        .computeIfAbsent(method.getBeanType().getName(), k -> new TreeSet<>())
                        .addAll(patternsOf(info));
            }
        });

        assertThat(testSourcedHandlers)
                .as("controllers compiled from src/test/java are mounted in the spec-dump context "
                        + "— they pollute the COMMITTED %s. There is no list to add them to: make "
                        + "the probe a NESTED class of its test (Boot's TestTypeExcludeFilter "
                        + "hides those) or move it out of a component-scanned package", SPEC_PATH)
                .isEmpty();
    }

    /**
     * The document half of the same invariant: every path springdoc emitted must be one a handler
     * compiled from {@code src/main/java} actually maps. Catches a phantom path arriving from
     * anywhere at all — a leaked probe, a springdoc customizer, a future scan of another tree —
     * without enumerating what "phantom" means in advance.
     *
     * <p>Safe against false positives here because springdoc is confined to
     * {@code springdoc.packages-to-scan: net.hugmesh.adminbff} and this module declares no
     * functional {@code RouterFunction} routes and no regex path variables, so every emitted path
     * is the verbatim pattern string of an annotated handler. {@code mainPatterns} is deliberately
     * a SUPERSET (it also holds springdoc's and the framework's own routes) — the assertion is
     * one-directional on purpose: an undocumented handler is a springdoc concern, a documented
     * non-handler is a broken contract.
     */
    private void assertOnlyMainSourcedPaths(JsonNode tree) {
        Set<String> mainPatterns = new TreeSet<>();
        handlerMapping.getHandlerMethods().forEach((info, method) -> {
            if (!ExcludeTestSourcedControllers.isTestSourced(method.getBeanType())) {
                mainPatterns.addAll(patternsOf(info));
            }
        });

        Set<String> specPaths = new TreeSet<>();
        tree.path("paths").fieldNames().forEachRemaining(specPaths::add);

        // Sanity on the comparison itself: an empty side would make the subset check vacuous.
        assertThat(specPaths).as("the dumped spec must describe paths").isNotEmpty();
        assertThat(mainPatterns).as("the production routing table must be non-empty").isNotEmpty();

        assertThat(specPaths)
                .as("every path in the dumped spec must be served by a handler compiled from "
                        + "src/main/java; anything else is a phantom endpoint in a contract the "
                        + "ng-openapi-gen typed clients and the docs pipeline consume")
                .isSubsetOf(mainPatterns);
    }

    private static Set<String> patternsOf(RequestMappingInfo info) {
        Set<String> patterns = new TreeSet<>();
        PatternsRequestCondition condition = info.getPatternsCondition();
        if (condition != null) {
            condition.getPatterns().forEach(pattern -> patterns.add(pattern.getPatternString()));
        }
        return patterns;
    }

    /**
     * The {@code Accept: application/json} header is REQUIRED. springdoc-webflux's
     * {@code openApiResource} only renders the spec for the JSON media type; a default
     * ({@code *}/{@code *}) Accept falls through to an empty {@code {}} text/plain body.
     */
    private JsonNode fetchSpec() throws Exception {
        String raw = client.get().uri("/v3/api-docs")
                .accept(MediaType.APPLICATION_JSON)
                .exchange()
                .expectStatus().isOk()
                .expectBody(String.class)
                .returnResult()
                .getResponseBody();

        assertThat(raw).as("springdoc must serve a non-empty /v3/api-docs").isNotBlank();
        return STABLE_MAPPER.readTree(raw);
    }
}
