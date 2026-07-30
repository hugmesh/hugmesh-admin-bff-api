package systems.hugmesh.adminbff.imagegen;

import org.junit.jupiter.api.Test;
import org.yaml.snakeyaml.Yaml;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * OFFLINE structural pin of {@code jobs/image-gen-admission.yaml} — the admission-layer
 * {@code hugmesh-image-spec-} prefix pin the operator applies alongside
 * {@code jobs/image-gen-rbac.yaml}. The live semantics are proven by
 * {@link ImageGenAdmissionKindE2eTest} (dark, kind-gated); THIS test keeps the shipped file
 * honest on every plain {@code ./mvnw test} run:
 * <ul>
 *   <li>the file parses as exactly TWO YAML documents — the policy and its binding;</li>
 *   <li>the load-bearing fields survive edits: {@code failurePolicy: Fail} (fail-closed),
 *       all three write operations on core-v1 configmaps, the matchCondition pinned to the
 *       admin-bff ServiceAccount, the {@code targetName} variable's per-operation
 *       resolution, the two-clause prefix validation, and the binding's
 *       {@code Deny} action + namespaceSelector confinement to hugmesh-backend;</li>
 *   <li>{@code message} stays single-line (the API server rejects a {@code message}
 *       containing line breaks) and no {@code messageExpression} string literal spans a
 *       line break (a CEL literal cannot);</li>
 *   <li>REGRESSION GUARD (review mustFix, 2026-07): the file must never again claim that a
 *       generateName CREATE reaches admission nameless. That is true only for MUTATING
 *       admission — ValidatingAdmissionPolicy runs after the registry generates the final
 *       name, so the pin evaluates the real generated name (see the e2e's generateName
 *       leg).</li>
 * </ul>
 */
class ImageGenAdmissionYamlTest {

    private static final String RESOURCE = "/jobs/image-gen-admission.yaml";
    private static final String POLICY_NAME = "hugmesh-image-spec-prefix-pin";
    private static final String ADMIN_BFF_USER =
            "system:serviceaccount:hugmesh-backend:admin-bff";
    /** Must match the launcher's per-build ConfigMap naming in ImageBuildOrchestrator. */
    private static final String PREFIX = "hugmesh-image-spec-";

    private static String rawFile() {
        try (InputStream in = ImageGenAdmissionYamlTest.class.getResourceAsStream(RESOURCE)) {
            assertThat(in).as("classpath resource %s exists", RESOURCE).isNotNull();
            return new String(in.readAllBytes(), StandardCharsets.UTF_8);
        } catch (Exception e) {
            throw new AssertionError("failed reading " + RESOURCE, e);
        }
    }

    private static List<Map<String, Object>> docs() {
        List<Map<String, Object>> docs = new ArrayList<>();
        for (Object doc : new Yaml().loadAll(rawFile())) {
            if (doc != null) {                       // leading comment-only chunk parses null
                @SuppressWarnings("unchecked")
                Map<String, Object> map = (Map<String, Object>) doc;
                docs.add(map);
            }
        }
        return docs;
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> path(Map<String, Object> root, String... keys) {
        Map<String, Object> cur = root;
        for (String k : keys) {
            Object next = cur.get(k);
            assertThat(next).as("key '%s' present and a mapping", k).isInstanceOf(Map.class);
            cur = (Map<String, Object>) next;
        }
        return cur;
    }

    @SuppressWarnings("unchecked")
    private static List<Map<String, Object>> listAt(Map<String, Object> map, String key) {
        Object v = map.get(key);
        assertThat(v).as("key '%s' present and a sequence", key).isInstanceOf(List.class);
        return (List<Map<String, Object>>) v;
    }

    @SuppressWarnings("unchecked")
    private static List<Object> scalarsAt(Map<String, Object> map, String key) {
        Object v = map.get(key);
        assertThat(v).as("key '%s' present and a sequence", key).isInstanceOf(List.class);
        return (List<Object>) v;
    }

    @Test
    void parsesAsPolicyPlusBinding_withTheLoadBearingFields() {
        List<Map<String, Object>> docs = docs();
        assertThat(docs).as("policy + binding, nothing else").hasSize(2);

        // ── doc 1: the ValidatingAdmissionPolicy ────────────────────────────────────────
        Map<String, Object> policy = docs.get(0);
        assertThat(policy.get("apiVersion")).isEqualTo("admissionregistration.k8s.io/v1");
        assertThat(policy.get("kind")).isEqualTo("ValidatingAdmissionPolicy");
        assertThat(path(policy, "metadata").get("name")).isEqualTo(POLICY_NAME);

        Map<String, Object> spec = path(policy, "spec");
        assertThat(spec.get("failurePolicy")).as("fail closed").isEqualTo("Fail");

        Map<String, Object> rule =
                listAt(path(spec, "matchConstraints"), "resourceRules").get(0);
        assertThat(scalarsAt(rule, "apiGroups")).containsExactly("");
        assertThat(scalarsAt(rule, "apiVersions")).containsExactly("v1");
        assertThat(scalarsAt(rule, "resources"))
                .containsExactly("configmaps");
        assertThat(scalarsAt(rule, "operations"))
                .as("every configmaps write there is")
                .containsExactlyInAnyOrder("CREATE", "UPDATE", "DELETE");

        Map<String, Object> match = listAt(spec, "matchConditions").get(0);
        assertThat((String) match.get("expression"))
                .as("scoped to exactly the admin-bff SA")
                .contains("request.userInfo.username")
                .contains("'" + ADMIN_BFF_USER + "'");

        Map<String, Object> variable = listAt(spec, "variables").get(0);
        assertThat(variable.get("name")).isEqualTo("targetName");
        assertThat((String) variable.get("expression"))
                .as("per-operation name resolution with null/has() guards")
                .contains("request.operation == 'DELETE'")
                .contains("oldObject.metadata.name")
                .contains("object.metadata.name")
                .contains("has(request.name) ? request.name : ''");

        Map<String, Object> validation = listAt(spec, "validations").get(0);
        assertThat((String) validation.get("expression"))
                .as("empty-name defense-in-depth clause AND the prefix pin itself")
                .contains("variables.targetName != ''")
                .contains("variables.targetName.startsWith('" + PREFIX + "')");
        assertThat(validation.get("reason")).isEqualTo("Forbidden");
        assertThat((String) validation.get("message"))
                .as("the API server rejects a message containing line breaks")
                .isNotBlank().doesNotContain("\n");
        // The messageExpression CEL SOURCE may span lines (CEL newlines are whitespace;
        // the folded scalar keeps breaks around more-indented lines) — but no double-quoted
        // CEL string literal may itself span a line break, or the expression won't compile.
        String messageExpression = (String) validation.get("messageExpression");
        assertThat(messageExpression).isNotBlank().contains("\"image-spec prefix pin: \"");
        for (String line : messageExpression.split("\n", -1)) {
            assertThat(line.chars().filter(c -> c == '"').count() % 2)
                    .as("every CEL string literal opens AND closes on one line: %s", line)
                    .isZero();
        }

        // ── doc 2: the binding that ENFORCES it, confined to hugmesh-backend ─────────
        Map<String, Object> binding = docs.get(1);
        assertThat(binding.get("apiVersion")).isEqualTo("admissionregistration.k8s.io/v1");
        assertThat(binding.get("kind")).isEqualTo("ValidatingAdmissionPolicyBinding");
        assertThat(path(binding, "metadata").get("name")).isEqualTo(POLICY_NAME);

        Map<String, Object> bindingSpec = path(binding, "spec");
        assertThat(bindingSpec.get("policyName")).isEqualTo(POLICY_NAME);
        assertThat(scalarsAt(bindingSpec, "validationActions"))
                .as("hard enforcement, not Warn/Audit").containsExactly("Deny");
        assertThat(path(bindingSpec, "matchResources", "namespaceSelector", "matchLabels"))
                .as("blast radius pinned to the RBAC grant's namespace")
                .containsEntry("kubernetes.io/metadata.name", "hugmesh-backend");
    }

    /**
     * Review mustFix regression guard: validating admission sees the FINAL generated name
     * of a generateName CREATE (the registry generates it before validation runs; only
     * mutating admission sees the name-less object). The file once claimed the opposite —
     * keep the disproved premise from creeping back into the comments or the CEL.
     */
    @Test
    void neverReclaimsTheNamelessGenerateNamePremise() {
        assertThat(rawFile())
                .doesNotContain("NOT generated the name yet")
                .doesNotContain("name unset at admission");
    }
}
