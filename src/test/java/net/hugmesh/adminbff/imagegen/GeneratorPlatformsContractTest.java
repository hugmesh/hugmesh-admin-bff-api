package net.hugmesh.adminbff.imagegen;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.validation.ConstraintViolation;
import jakarta.validation.Validation;
import jakarta.validation.Validator;
import jakarta.validation.ValidatorFactory;
import net.hugmesh.adminbff.sshterminal.ImageBuild;
import net.hugmesh.adminbff.web.dto.BatchImageSpec;
import net.hugmesh.adminbff.web.dto.BatchTriggerImageBuildRequest;
import net.hugmesh.commons.web.ApiException;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.core.io.ClassPathResource;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * CONTRACT: the web admin channel accepts EVERY platform the vendored generator worklist schema
 * lists, and refuses anything else with a reason (issue hugmesh-admin-bff-api#162, part of the
 * platform expansion, hugmesh-generator#1045).
 *
 * <p>The enums are parsed here, straight from the vendored resource, NOT through
 * {@link GeneratorPlatforms}: a loader that dropped or invented a value must not be able to
 * agree with itself. Each platform goes through both gates a batch request meets — bean
 * validation of {@link BatchImageSpec} (the HTTP 400 path) and {@link WorklistEnvelopeValidator}
 * (the service gate) — and through the manifest render the image worker receives.
 */
class GeneratorPlatformsContractTest {

    private static final ObjectMapper M = new ObjectMapper();
    private static final String SCHEMA = "schema/worklist.v1.schema.json";

    /** The platforms the hand list carried before this change; the schema must still list them. */
    private static final Set<String> LEGACY_SIX =
            Set.of("x86", "rpi5", "frite", "jetson", "orangepi5", "orangepizero2");

    private static ValidatorFactory factory;
    private static Validator beanValidator;
    private final WorklistEnvelopeValidator validator = new WorklistEnvelopeValidator();

    @BeforeAll
    static void setUpValidation() {
        factory = Validation.buildDefaultValidatorFactory();
        beanValidator = factory.getValidator();
    }

    @AfterAll
    static void closeValidation() {
        factory.close();
    }

    private static JsonNode schema() {
        try (InputStream in = new ClassPathResource(SCHEMA).getInputStream()) {
            return M.readTree(in);
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }

    private static List<String> schemaEnum(String def) {
        List<String> out = new ArrayList<>();
        schema().path("$defs").path(def).path("properties").path("platform").path("enum")
                .forEach(v -> out.add(v.asText()));
        return out;
    }

    static Stream<String> entryPlatforms() {
        return schemaEnum("worklistEntry").stream();
    }

    static Stream<String> imageSpecPlatforms() {
        return schemaEnum("imageConfig").stream();
    }

    private static JsonNode json(String s) {
        try {
            return M.readTree(s);
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }

    private static BatchImageSpec entry(String platform, JsonNode spec) {
        return new BatchImageSpec("brandx/alice", "primary", platform, false, spec);
    }

    private static BatchTriggerImageBuildRequest env(BatchImageSpec e) {
        return new BatchTriggerImageBuildRequest("hugmesh-worklist/v1", null, List.of(e), 1);
    }

    private static String reason(Throwable t) {
        assertThat(t).isInstanceOf(ApiException.class);
        assertThat(((ApiException) t).status().value()).isEqualTo(400);
        return t.getMessage();
    }

    // ── the schema is real (no vacuous pass) ────────────────────────────────────

    @Test
    void vendoredSchema_listsTheLegacyPlatformsAndMore() {
        List<String> entry = schemaEnum("worklistEntry");
        assertThat(entry).as("worklistEntry platform enum").isNotEmpty().containsAll(LEGACY_SIX);
        assertThat(schemaEnum("imageConfig")).as("imageConfig platform enum")
                .isNotEmpty().containsAll(LEGACY_SIX);
        // The loader serves exactly what the schema lists, in schema order.
        assertThat(GeneratorPlatforms.entryPlatforms()).containsExactlyElementsOf(entry);
        assertThat(GeneratorPlatforms.imageSpecPlatforms())
                .containsExactlyElementsOf(schemaEnum("imageConfig"));
    }

    // ── every schema platform is accepted ───────────────────────────────────────

    @ParameterizedTest(name = "entry platform {0} passes bean validation")
    @MethodSource("entryPlatforms")
    void everySchemaPlatform_passesBeanValidation(String platform) {
        assertThat(beanValidator.validate(entry(platform, null))).isEmpty();
    }

    @ParameterizedTest(name = "entry platform {0} passes the envelope validator")
    @MethodSource("entryPlatforms")
    void everySchemaPlatform_passesEnvelopeValidator(String platform) {
        assertThatCode(() -> validator.validate(env(entry(platform, null))))
                .doesNotThrowAnyException();
    }

    @ParameterizedTest(name = "imageSpec platform {0} passes the envelope validator")
    @MethodSource("imageSpecPlatforms")
    void everySchemaImageSpecPlatform_passesEnvelopeValidator(String platform) {
        JsonNode spec = json("{\"role\":\"gateway\",\"platform\":\"" + platform + "\"}");
        assertThatCode(() -> validator.validate(env(entry("x86", spec))))
                .doesNotThrowAnyException();
    }

    @ParameterizedTest(name = "entry platform {0} renders into the image-gen manifest")
    @MethodSource("entryPlatforms")
    void everySchemaPlatform_rendersIntoTheManifest(String platform) {
        // The platform is substituted into a quoted YAML scalar (yamlSafe) and stored in
        // image_build.hardware_class varchar(64).
        assertThat(platform.length()).isLessThanOrEqualTo(64);
        ImageBuildOrchestrator orch = new ImageBuildOrchestrator(null, new NoopImageJobLauncher(), 64);
        ImageBuild build = new ImageBuild("00000000-0000-0000-0000-000000000162", null, "admin@x",
                "brandx/alice", "brandx", ImageBuild.IMAGE_PRIMARY, platform, null,
                ImageBuild.STATUS_QUEUED, true, null, null, null, null, null, null, null);
        assertThat(orch.renderManifest(build))
                .contains("{ name: HARDWARE_CLASS, value: \"" + platform + "\" }");
    }

    // ── anything else is refused, with a reason ─────────────────────────────────

    @ParameterizedTest(name = "unknown platform [{0}] is refused by bean validation")
    @ValueSource(strings = {"toaster", "X86", "rpi5x", "rpi5\n", " rpi5", "x86-64",
            "x86|rpi5", "orangepi3_lts", "${x86}"})
    void unknownPlatform_refusedByBeanValidation(String platform) {
        Set<ConstraintViolation<BatchImageSpec>> v = beanValidator.validate(entry(platform, null));
        assertThat(v).hasSize(1);
        ConstraintViolation<BatchImageSpec> only = v.iterator().next();
        assertThat(only.getPropertyPath().toString()).isEqualTo("hardwareClass");
        assertThat(only.getMessage())
                .startsWith("must be a platform in the generator worklist schema (accepted: ")
                .contains(GeneratorPlatforms.describeEntryPlatforms());
        for (String p : schemaEnum("worklistEntry")) {
            assertThat(only.getMessage()).contains(p);
        }
    }

    @ParameterizedTest(name = "unknown platform [{0}] is refused by the envelope validator")
    @ValueSource(strings = {"toaster", "X86", "rpi5x", "rpi5\n", " rpi5", "x86-64", "x86|rpi5", ""})
    void unknownPlatform_refusedByEnvelopeValidator(String platform) {
        assertThatThrownBy(() -> validator.validate(env(entry(platform, null))))
                .satisfies(t -> assertThat(reason(t))
                        .startsWith("entry 0 platform '")
                        .contains("is not in the generator worklist schema (accepted: ")
                        .contains(GeneratorPlatforms.describeEntryPlatforms()));
    }

    @Test
    void missingPlatform_refusedByEnvelopeValidator() {
        assertThatThrownBy(() -> validator.validate(env(entry(null, null))))
                .satisfies(t -> assertThat(reason(t)).startsWith("entry 0 platform (missing)"));
    }

    @ParameterizedTest(name = "unknown imageSpec platform {0} is refused")
    @ValueSource(strings = {"\"toaster\"", "\"X86\"", "\"x86-64\"", "7", "[\"x86\"]", "{\"p\":\"x86\"}"})
    void unknownImageSpecPlatform_refused(String platformJson) {
        JsonNode spec = json("{\"role\":\"gateway\",\"platform\":" + platformJson + "}");
        assertThatThrownBy(() -> validator.validate(env(entry("x86", spec))))
                .satisfies(t -> assertThat(reason(t))
                        .startsWith("entry 0 imageSpec platform '")
                        .contains("is not in the generator worklist schema (accepted: ")
                        .contains(GeneratorPlatforms.describeImageSpecPlatforms()));
    }

    @Test
    void longRefusedValue_isCutInTheReason() {
        String platform = "a".repeat(500);
        assertThatThrownBy(() -> validator.validate(env(entry(platform, null))))
                .satisfies(t -> assertThat(reason(t))
                        .contains("'" + "a".repeat(40) + "...'")
                        .doesNotContain("a".repeat(41)));
    }

    // ── no hand list is left in production code ─────────────────────────────────

    @Test
    void noHandWrittenPlatformAlternationInMainSources() throws IOException {
        Path main = Path.of("src/main/java");
        assertThat(main).isDirectory();
        List<String> platforms = schemaEnum("worklistEntry");
        List<String> hits = new ArrayList<>();
        try (Stream<Path> files = Files.walk(main)) {
            for (Path f : (Iterable<Path>) files.filter(p -> p.toString().endsWith(".java"))::iterator) {
                String src = Files.readString(f, StandardCharsets.UTF_8);
                for (String a : platforms) {
                    for (String b : platforms) {
                        if (a.equals(b)) {
                            continue;
                        }
                        for (String sep : new String[] {"|", ", ", ","}) {
                            if (src.contains("\"" + a + sep + b) || src.contains(a + sep + b + "\"")) {
                                hits.add(main.relativize(f) + ": " + a + sep + b);
                            }
                        }
                    }
                }
            }
        }
        assertThat(hits).as("a hand-written platform list in production code; read "
                + "GeneratorPlatforms (the vendored worklist schema) instead").isEmpty();
    }
}
