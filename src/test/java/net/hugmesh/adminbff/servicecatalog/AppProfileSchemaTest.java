package net.hugmesh.adminbff.servicecatalog;

import com.fasterxml.jackson.databind.JsonNode;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.BiConsumer;
import java.util.regex.Pattern;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * {@link AppProfileSchema} — the SERVER half of the app-profile contract (issue #55).
 *
 * <p>Three jobs, in order of what actually protects the platform:
 * <ol>
 *   <li><b>Parity with the console.</b> Same verdict AND same message string for every class of
 *       refusal, so the operator sees one vocabulary whichever half catches the mistake. The
 *       expected strings here are the ones {@code src/app/app-profile-schema.ts} produces.</li>
 *   <li><b>The anchoring trap.</b> A byte-identical schema plus an ordinary
 *       {@code Matcher.find()} accepts values the browser refuses. Pinned with the measurement
 *       that proves the test is not vacuous.</li>
 *   <li><b>Decision 37, ratified 2026-09-17.</b> {@code ROLE_<UPPER>} roles, STRICT unknown
 *       keys, {@code exposure.mfaRequired} kept — asserted directly so a later change cannot
 *       quietly take the branch the operator declined.</li>
 * </ol>
 */
class AppProfileSchemaTest {

    // ── helpers ─────────────────────────────────────────────────────────────────

    private static Map<String, String> errors(String body) {
        return AppProfileSchema.asFields(AppProfileSchema.validate(body));
    }

    private static void assertValid(String body) {
        assertThat(AppProfileSchema.validate(body))
                .withFailMessage("expected %s to be VALID, got %s", body, errors(body))
                .isEmpty();
    }

    private static void assertRefused(String body, String path, String message) {
        Map<String, String> errs = errors(body);
        assertThat(errs).withFailMessage("expected a refusal at %s for %s, got %s", path, body, errs)
                .containsEntry(path, message);
    }

    /** Walk every subschema NODE of the committed schema, depth-first. */
    private static void walkNodes(JsonNode node, String at, BiConsumer<String, JsonNode> visit) {
        visit.accept(at, node);
        JsonNode props = node.get("properties");
        if (props != null) {
            props.fieldNames().forEachRemaining(name -> walkNodes(props.get(name), at + "." + name, visit));
        }
        JsonNode items = node.get("items");
        if (items != null) {
            walkNodes(items, at + "[]", visit);
        }
    }

    // ── the committed file is a schema this interpreter can actually enforce ─────

    @Nested
    class TheCommittedFile {

        @Test
        void usesOnlyKeywordsTheInterpreterImplements() {
            // An unimplemented keyword is SKIPPED by the interpreter, i.e. it fails OPEN, and no
            // runtime check can see that. This walk is the only thing that can.
            List<String> unknown = new ArrayList<>();
            walkNodes(AppProfileSchema.schema(), "$", (at, node) ->
                    node.fieldNames().forEachRemaining(kw -> {
                        if (!AppProfileSchema.SUPPORTED_KEYWORDS.contains(kw)) {
                            unknown.add(at + ":" + kw);
                        }
                    }));
            assertThat(unknown).isEmpty();
        }

        @Test
        void declaresAStringTypeOnEverySubschema() {
            // A typeless node would have ALL of its keywords skipped — the simplest fail-open.
            List<String> typeless = new ArrayList<>();
            walkNodes(AppProfileSchema.schema(), "$", (at, node) -> {
                JsonNode type = node.get("type");
                if (type == null || !type.isTextual()) {
                    typeless.add(at);
                }
            });
            assertThat(typeless).isEmpty();
        }

        @Test
        void closesEveryObject() {
            List<String> open = new ArrayList<>();
            walkNodes(AppProfileSchema.schema(), "$", (at, node) -> {
                if ("object".equals(node.path("type").asText()) && !node.path("additionalProperties").isBoolean()) {
                    open.add(at);
                }
            });
            assertThat(open).isEmpty();
        }

        @Test
        void everyPatternCompilesAndEveryExampleSatisfiesItsOwnSchema() {
            walkNodes(AppProfileSchema.schema(), "$", (at, node) -> {
                JsonNode pattern = node.get("pattern");
                if (pattern != null) {
                    assertThat(Pattern.compile(pattern.textValue())).isNotNull();
                }
            });
            // The ROOT examples are whole profiles: they must validate as they stand.
            JsonNode rootExamples = AppProfileSchema.schema().path("examples");
            assertThat(rootExamples.isArray()).isTrue();
            for (JsonNode example : rootExamples) {
                assertValid(example.toString());
            }
        }
    }

    // ── parity with the console, class by class ─────────────────────────────────

    @Nested
    class ValidBodies {

        @Test
        void theMinimalProfileAndTheEditorDefault() {
            assertValid("{}");
            assertValid("{\"resources\":{\"cpu\":\"500m\",\"memory\":\"512Mi\"}}");
        }

        @Test
        void nullAndBlankAreTheMinimalProfile() {
            // The column is nullable and the console sends blank text as {} — both halves agree.
            assertThat(AppProfileSchema.validate(null)).isEmpty();
            assertThat(AppProfileSchema.validate("")).isEmpty();
            assertThat(AppProfileSchema.validate("   \n  ")).isEmpty();
        }

        @Test
        void aProfileUsingEverySectionAndField() {
            assertValid("""
                    {"resources":{"cpu":"1","memory":"1Gi"},
                     "roles":["ROLE_ADMIN","ROLE_MESH"],
                     "certs":{"altNames":["owncast","owncast.acme-be.svc.cluster.local"],"ttl":"720h"},
                     "exposure":{"routes":["/api/owncast/","/ws/owncast/**"],"ports":[8080,8443],"mfaRequired":true}}""");
        }

        @Test
        void theKubernetesQuantitySpellingsThePlatformUses() {
            for (String cpu : List.of("500m", "1", "0.5", "2")) {
                assertValid("{\"resources\":{\"cpu\":\"" + cpu + "\"}}");
            }
            for (String mem : List.of("512Mi", "1Gi", "256M", "1024", "0.5Gi")) {
                assertValid("{\"resources\":{\"memory\":\"" + mem + "\"}}");
            }
        }
    }

    @Nested
    class EachInvalidClassNamesItsField {

        @Test
        void textThatIsNotJsonIsOneErrorAtTheRoot() {
            List<AppProfileSchema.FieldError> errs = AppProfileSchema.validate("{not json");
            assertThat(errs).hasSize(1);
            assertThat(errs.get(0).path()).isEqualTo("$");
            assertThat(errs.get(0).message()).startsWith("not valid JSON (");
        }

        @Test
        void aRootThatIsNotAnObject() {
            for (String raw : List.of("[]", "\"cpu\"", "42", "null", "true")) {
                assertRefused(raw, "$", "must be an object");
            }
        }

        @Test
        void theLegacyFlatBodyNamesBothUnknownKeysAndListsTheAllowedSections() {
            Map<String, String> errs = errors("{\"cpu\":\"500m\",\"memory\":\"512Mi\"}");
            assertThat(errs).containsExactly(
                    Map.entry("cpu", "unknown field (allowed here: resources, roles, certs, exposure)"),
                    Map.entry("memory", "unknown field (allowed here: resources, roles, certs, exposure)"));
        }

        @Test
        void anUnknownNestedFieldNamesItsDottedPathAndWhatIsAllowedThere() {
            assertRefused("{\"resources\":{\"cpu\":\"500m\",\"limits\":{}}}",
                    "resources.limits", "unknown field (allowed here: cpu, memory)");
            assertRefused("{\"exposure\":{\"public\":true}}",
                    "exposure.public", "unknown field (allowed here: routes, ports, mfaRequired)");
            assertRefused("{\"certs\":{\"keyAlgorithm\":\"ec\"}}",
                    "certs.keyAlgorithm", "unknown field (allowed here: altNames, ttl)");
        }

        @Test
        void aWrongTypeAtEveryLevel() {
            assertRefused("{\"resources\":\"500m\"}", "resources", "must be an object");
            assertRefused("{\"resources\":{\"cpu\":500}}", "resources.cpu", "must be a string");
            assertRefused("{\"roles\":\"ROLE_ADMIN\"}", "roles", "must be an array");
            assertRefused("{\"roles\":[1]}", "roles[0]", "must be a string");
            assertRefused("{\"certs\":[]}", "certs", "must be an object");
            assertRefused("{\"exposure\":{\"ports\":[\"8080\"]}}", "exposure.ports[0]", "must be an integer");
            assertRefused("{\"exposure\":{\"ports\":[80.5]}}", "exposure.ports[0]", "must be an integer");
            assertRefused("{\"exposure\":{\"mfaRequired\":\"yes\"}}", "exposure.mfaRequired", "must be a boolean");
            assertRefused("{\"exposure\":{\"routes\":null}}", "exposure.routes", "must be an array");
        }

        @Test
        void aValueThatDoesNotMatchItsPatternCarriesTheExampleHint() {
            assertRefused("{\"resources\":{\"cpu\":\"lots\"}}", "resources.cpu",
                    "must match ^([0-9]+(\\.[0-9]+)?|[0-9]+m)$ (e.g. \"500m\", \"1\", \"0.5\")");
            assertRefused("{\"resources\":{\"memory\":\"512MB\"}}", "resources.memory",
                    "must match ^[0-9]+(\\.[0-9]+)?(k|M|G|T|P|E|Ki|Mi|Gi|Ti|Pi|Ei)?$ (e.g. \"512Mi\", \"1Gi\", \"256M\")");
            assertRefused("{\"roles\":[\"ROLE_ADMIN\",\"role\"]}", "roles[1]",
                    "must match ^ROLE_[A-Z][A-Z0-9_]*$ (e.g. \"ROLE_ADMIN\", \"ROLE_MESH\")");
            assertRefused("{\"certs\":{\"ttl\":\"30d\"}}", "certs.ttl",
                    "must match ^([0-9]+(h|m|s))+$ (e.g. \"720h\", \"168h\", \"1h30m\")");
            assertRefused("{\"certs\":{\"altNames\":[\"Bad_Host\"]}}", "certs.altNames[0]",
                    "must match ^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$"
                            + " (e.g. \"owncast\", \"owncast.acme-be.svc.cluster.local\")");
            assertRefused("{\"exposure\":{\"routes\":[\"api/owncast/\"]}}", "exposure.routes[0]",
                    "must match ^/[A-Za-z0-9/_.-]*(\\*\\*)?$"
                            + " (e.g. \"/api/owncast/\", \"/api/owncast/**\", \"/ws/owncast/**\")");
            // The seeded whole-surface forms the gateway really ships stay expressible.
            assertValid("{\"exposure\":{\"routes\":[\"/\",\"/**\"]}}");
        }

        @Test
        void aPortOutsideOneToSixtyFiveFiveThreeFive() {
            assertRefused("{\"exposure\":{\"ports\":[0]}}", "exposure.ports[0]", "must be at least 1");
            assertRefused("{\"exposure\":{\"ports\":[65536]}}", "exposure.ports[0]", "must be at most 65535");
            assertRefused("{\"exposure\":{\"ports\":[8080,-1]}}", "exposure.ports[1]", "must be at least 1");
        }

        @Test
        void duplicateArrayItems() {
            assertRefused("{\"roles\":[\"ROLE_ADMIN\",\"ROLE_ADMIN\"]}", "roles[1]", "duplicates an earlier item");
            assertRefused("{\"exposure\":{\"ports\":[8080,8080]}}", "exposure.ports[1]", "duplicates an earlier item");
            // 1 and 1.0 are the SAME number in the browser (JSON.stringify collapses both to "1"),
            // so uniqueItems must collide here too or the two halves disagree.
            assertRefused("{\"exposure\":{\"ports\":[8080,8080.0]}}", "exposure.ports[1]", "duplicates an earlier item");
        }

        @Test
        void tooManyItemsAndTooLongAString() {
            StringBuilder roles = new StringBuilder("{\"roles\":[");
            for (int i = 0; i < 33; i++) {
                roles.append(i == 0 ? "" : ",").append("\"ROLE_R").append(i).append('"');
            }
            assertRefused(roles.append("]}").toString(), "roles", "must have at most 32 item(s)");
            assertRefused("{\"resources\":{\"cpu\":\"" + "9".repeat(40) + "\"}}",
                    "resources.cpu", "must be at most 32 character(s)");
        }

        @Test
        void everyErrorIsReportedAtOnceNotJustTheFirst() {
            Map<String, String> errs =
                    errors("{\"resources\":{\"cpu\":\"lots\"},\"roles\":[\"x\"],\"bogus\":1,\"exposure\":{\"ports\":[0]}}");
            assertThat(errs.keySet())
                    .containsExactlyInAnyOrder("resources.cpu", "roles[0]", "bogus", "exposure.ports[0]");
        }

        @Test
        void twoRefusalsAtTheSamePathAreBothKeptInTheFieldsMap() {
            // A 40-character value that is ALSO not a quantity trips maxLength AND pattern at the
            // same path. The console lists both; folding the list into the single-valued
            // {"fields": …} map must not silently drop one of them.
            Map<String, String> errs = errors("{\"resources\":{\"cpu\":\"" + "x".repeat(40) + "\"}}");
            assertThat(errs).containsOnlyKeys("resources.cpu");
            assertThat(errs.get("resources.cpu"))
                    .contains("must be at most 32 character(s)")
                    .contains("must match ^([0-9]+(\\.[0-9]+)?|[0-9]+m)$");
        }
    }

    // ── the two things ONLY the server can decide ───────────────────────────────

    @Nested
    class TheServerOnlyRefusals {

        @Test
        void aDuplicateKeyIsRefused_theOneClassTheBrowserCannotCatch() {
            // JSON.parse is last-wins and cannot report a duplicate, so the console is structurally
            // incapable of refusing this. The server is the only half that can, and refusing is the
            // safe choice: a template whose cpu is written twice has no single intended meaning.
            List<AppProfileSchema.FieldError> errs =
                    AppProfileSchema.validate("{\"resources\":{\"cpu\":\"500m\",\"cpu\":\"2\"}}");
            assertThat(errs).hasSize(1);
            assertThat(errs.get(0).path()).isEqualTo("$");
            assertThat(errs.get(0).message()).contains("not valid JSON").contains("Duplicate field");
        }

        @Test
        void patternsAreAnchoredOnTheWHOLEValue_theFindVsMatchesTrap() {
            String cpuPattern = AppProfileSchema.schema()
                    .path("properties").path("resources").path("properties").path("cpu")
                    .path("pattern").textValue();

            // THE MEASUREMENT that makes this test non-vacuous: an ordinary find()-based validator
            // over this very pattern ACCEPTS the trailing newline (java.util.regex lets $ match
            // before a final line terminator), while the browser's RegExp.test() refuses it.
            assertThat(Pattern.compile(cpuPattern).matcher("500m\n").find())
                    .withFailMessage("the find()/matches() divergence this guard exists for is gone —"
                            + " re-measure before deleting the guard")
                    .isTrue();
            assertThat(Pattern.compile(cpuPattern).matcher("500m\n").matches()).isFalse();

            // So the validator must refuse it, exactly as the console does.
            assertRefused("{\"resources\":{\"cpu\":\"500m\\n\"}}", "resources.cpu",
                    "must match ^([0-9]+(\\.[0-9]+)?|[0-9]+m)$ (e.g. \"500m\", \"1\", \"0.5\")");
            for (String terminator : List.of("\\r\\n", "\\u0085", "\\u2028")) {
                Map<String, String> errs = errors("{\"resources\":{\"cpu\":\"500m" + terminator + "\"}}");
                assertThat(errs).withFailMessage("500m%s must be refused", terminator)
                        .containsKey("resources.cpu");
            }
            // And the same for every other patterned leaf.
            assertRefused("{\"roles\":[\"ROLE_ADMIN\\n\"]}", "roles[0]",
                    "must match ^ROLE_[A-Z][A-Z0-9_]*$ (e.g. \"ROLE_ADMIN\", \"ROLE_MESH\")");
            assertRefused("{\"certs\":{\"ttl\":\"720h\\n\"}}", "certs.ttl",
                    "must match ^([0-9]+(h|m|s))+$ (e.g. \"720h\", \"168h\", \"1h30m\")");
            assertThat(errors("{\"exposure\":{\"routes\":[\"/api/x/**\\n\"]}}")).containsKey("exposure.routes[0]");
            assertThat(errors("{\"certs\":{\"altNames\":[\"owncast\\n\"]}}")).containsKey("certs.altNames[0]");
        }
    }

    // ── the interpreter fails CLOSED on a schema it cannot enforce ──────────────

    @Nested
    class FailsClosedOnAnUnenforceableSchema {

        /** A PROBE schema — not the committed file, which trips none of these. */
        private JsonNode probe(String leafJson) {
            String json = """
                    {"type":"object","additionalProperties":false,"properties":{
                      "certs":{"type":"object","additionalProperties":false,"properties":{
                        "keyAlgorithm": %s }}}}""".formatted(leafJson);
            try {
                return new com.fasterxml.jackson.databind.ObjectMapper().readTree(json);
            } catch (com.fasterxml.jackson.core.JsonProcessingException e) {
                throw new IllegalStateException(e);
            }
        }

        private String refusal(JsonNode schema, String body) {
            List<AppProfileSchema.FieldError> errs = AppProfileSchema.validateAgainst(schema, body);
            assertThat(errs).withFailMessage("expected a refusal for %s", body).isNotEmpty();
            StringBuilder sb = new StringBuilder();
            for (AppProfileSchema.FieldError e : errs) {
                sb.append(sb.isEmpty() ? "" : " | ").append(e.path()).append(": ").append(e.message());
            }
            return sb.toString();
        }

        @Test
        void aSubschemaWithNoTypeRefusesEVERYTHING_theSimplestFailOpen() {
            // Every branch of the interpreter is gated on `type`, so a typeless node would have ALL
            // of its keywords skipped and accept anything — and no keyword guard can see it, because
            // the node carries no UNKNOWN keyword, it carries none at all.
            JsonNode p = probe("{\"description\":\"a leaf added with no type keyword\"}");
            for (String body : List.of(
                    "{\"certs\":{\"keyAlgorithm\":\"absolutely-not-rsa-or-ec\"}}",
                    "{\"certs\":{\"keyAlgorithm\":12345}}",
                    "{\"certs\":{\"keyAlgorithm\":null}}",
                    "{\"certs\":{\"keyAlgorithm\":[1,2,3]}}",
                    "{\"certs\":{\"keyAlgorithm\":{\"nested\":{\"deep\":true}}}}")) {
                assertThat(refusal(p, body))
                        .isEqualTo("certs.keyAlgorithm: schema error: subschema declares no \"type\"");
            }
        }

        @Test
        void anUnsupportedTypeIsRefusedRatherThanAccepted() {
            assertThat(refusal(probe("{\"type\":\"null\"}"), "{\"certs\":{\"keyAlgorithm\":null}}"))
                    .isEqualTo("certs.keyAlgorithm: schema error: unsupported type \"null\"");
        }

        @Test
        void aNonBooleanAdditionalPropertiesIsRefusedRatherThanTreatedAsOpen() {
            JsonNode p;
            try {
                p = new com.fasterxml.jackson.databind.ObjectMapper().readTree(
                        "{\"type\":\"object\",\"additionalProperties\":{\"type\":\"string\"},\"properties\":{}}");
            } catch (com.fasterxml.jackson.core.JsonProcessingException e) {
                throw new IllegalStateException(e);
            }
            assertThat(refusal(p, "{\"anythingAtAll\":\"x\"}"))
                    .isEqualTo("$: schema error: unsupported additionalProperties (must be a boolean)");
        }

        @Test
        void aCorrectlyTypedValueUnderTheSameProbeIsStillAccepted() {
            assertThat(AppProfileSchema.validateAgainst(
                    probe("{\"type\":\"string\",\"pattern\":\"^(rsa|ec)$\"}"),
                    "{\"certs\":{\"keyAlgorithm\":\"ec\"}}")).isEmpty();
        }
    }

    // ── decision 37, ratified 2026-09-17 (hugmesh-generator#347) ────────────────

    @Nested
    class Decision37 {

        @Test
        void a_rolesAreCasdoorRoleUpperNamesNotThePerServiceRequiresRoleSlug() {
            assertThat(AppProfileSchema.schema().path("properties").path("roles")
                    .path("items").path("pattern").textValue())
                    .isEqualTo("^ROLE_[A-Z][A-Z0-9_]*$");
            for (String role : List.of("ROLE_ADMIN", "ROLE_SUPERADMIN", "ROLE_MESH", "ROLE_OWNCAST", "ROLE_APP_STORE")) {
                assertValid("{\"roles\":[\"" + role + "\"]}");
            }
            // The alternative the operator ruled against: the per-service requiresRole slug.
            for (String slug : List.of("owncast", "owncast-admin", "app-store", "Owncast", "role_owncast", "ROLE_owncast", "ROLE_")) {
                assertThat(errors("{\"roles\":[\"" + slug + "\"]}"))
                        .withFailMessage("%s must NOT be a valid role", slug)
                        .containsKey("roles[0]");
            }
        }

        @Test
        void b_strictOnUnknownKeys_additionalPropertiesFalseEverywhere() {
            assertThat(AppProfileSchema.schema().path("additionalProperties").booleanValue()).isFalse();
            for (String section : List.of("resources", "certs", "exposure")) {
                assertThat(AppProfileSchema.schema().path("properties").path(section)
                        .path("additionalProperties").booleanValue())
                        .withFailMessage("%s must stay closed", section).isFalse();
            }
            List<String> lenient = new ArrayList<>();
            walkNodes(AppProfileSchema.schema(), "$", (at, node) -> {
                if (node.path("additionalProperties").isBoolean() && node.path("additionalProperties").booleanValue()) {
                    lenient.add(at);
                }
            });
            assertThat(lenient).isEmpty();

            Map<String, String> expected = new LinkedHashMap<>();
            expected.put("{\"bogus\":1}", "bogus|unknown field (allowed here: resources, roles, certs, exposure)");
            expected.put("{\"resources\":{\"bogus\":1}}", "resources.bogus|unknown field (allowed here: cpu, memory)");
            expected.put("{\"certs\":{\"bogus\":1}}", "certs.bogus|unknown field (allowed here: altNames, ttl)");
            expected.put("{\"exposure\":{\"bogus\":1}}", "exposure.bogus|unknown field (allowed here: routes, ports, mfaRequired)");
            expected.forEach((body, spec) -> {
                String[] parts = spec.split("\\|", 2);
                assertRefused(body, parts[0], parts[1]);
            });
        }

        @Test
        void c_exposureMfaRequiredIsKept() {
            JsonNode mfa = AppProfileSchema.schema().path("properties").path("exposure")
                    .path("properties").path("mfaRequired");
            assertThat(mfa.isMissingNode())
                    .withFailMessage("exposure.mfaRequired was removed — decision 37c says KEEP it")
                    .isFalse();
            assertThat(mfa.path("type").asText()).isEqualTo("boolean");
            assertThat(mfa.path("description").asText()).contains("mfa_required");
            assertValid("{\"exposure\":{\"mfaRequired\":true}}");
            assertValid("{\"exposure\":{\"mfaRequired\":false}}");
            for (String bad : List.of("\"true\"", "1", "0", "null", "[]", "{}")) {
                assertRefused("{\"exposure\":{\"mfaRequired\":" + bad + "}}", "exposure.mfaRequired", "must be a boolean");
            }
        }

        @Test
        void theSectionsAreExactlyTheFourTheDecisionNames() {
            List<String> sections = new ArrayList<>();
            AppProfileSchema.schema().path("properties").fieldNames().forEachRemaining(sections::add);
            assertThat(sections).containsExactly("resources", "roles", "certs", "exposure");
        }
    }
}
