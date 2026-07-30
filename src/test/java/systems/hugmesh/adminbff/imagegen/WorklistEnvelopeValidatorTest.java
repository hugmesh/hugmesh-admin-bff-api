package systems.hugmesh.adminbff.imagegen;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import systems.hugmesh.commons.web.ApiException;
import systems.hugmesh.adminbff.web.dto.BatchImageSpec;
import systems.hugmesh.adminbff.web.dto.BatchTriggerImageBuildRequest;

import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * The FAIL-CLOSED worklist.v1 envelope validator — the spec-injection gate. Proves the
 * structural fences that make the IMAGE_SPEC_JSON channel safe (it bypasses renderManifest's
 * yamlSafe scalar guard, so the spec content MUST be fenced here BEFORE it is persisted /
 * written to a ConfigMap): schema discriminator, N<=16, platform enum, NO plaintext secrets,
 * package-atom charset, domain-name syntax, and no envelope-in-entry smuggling.
 */
class WorklistEnvelopeValidatorTest {

    private final WorklistEnvelopeValidator validator = new WorklistEnvelopeValidator();
    private static final ObjectMapper M = new ObjectMapper();

    private static JsonNode json(String s) {
        try {
            return M.readTree(s);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private static BatchImageSpec entry(String platform, JsonNode spec) {
        return new BatchImageSpec("brandx/alice", "primary", platform, false, spec);
    }

    private static BatchTriggerImageBuildRequest env(JsonNode base, List<BatchImageSpec> entries) {
        return new BatchTriggerImageBuildRequest("hugmesh-worklist/v1", base, entries, 1);
    }

    private static int status(Throwable t) {
        return ((ApiException) t).status().value();
    }

    @Test
    void validEnvelope_passes() {
        JsonNode base = json("{\"brand\":\"brandx\",\"domains\":[{\"name\":\"brandx.example\"}],"
                + "\"users\":[{\"username\":\"u\",\"domain\":\"brandx.example\"}]}");
        JsonNode spec = json("{\"role\":\"gateway\",\"platform\":\"rpi5\",\"packages_add\":\"app-editors/vim sys-apps/ripgrep\"}");
        assertThatCode(() -> validator.validate(env(base, List.of(entry("rpi5", spec)))))
                .doesNotThrowAnyException();
    }

    @Test
    void wrongSchema_400() {
        var req = new BatchTriggerImageBuildRequest("nope/v9", null, List.of(entry("rpi5", null)), 1);
        assertThatThrownBy(() -> validator.validate(req))
                .isInstanceOf(ApiException.class)
                .satisfies(e -> assertThat(status(e)).isEqualTo(400));
    }

    @Test
    void emptyEntries_400() {
        assertThatThrownBy(() -> validator.validate(env(null, List.of())))
                .satisfies(e -> assertThat(status(e)).isEqualTo(400));
    }

    @Test
    void moreThan16Entries_400() {
        List<BatchImageSpec> many = new ArrayList<>();
        for (int i = 0; i < 17; i++) many.add(entry("rpi5", null));
        assertThatThrownBy(() -> validator.validate(env(null, many)))
                .satisfies(e -> assertThat(status(e)).isEqualTo(400));
    }

    @Test
    void badPlatform_400() {
        assertThatThrownBy(() -> validator.validate(env(null, List.of(entry("toaster", null)))))
                .satisfies(e -> assertThat(status(e)).isEqualTo(400));
    }

    @Test
    void plaintextSecretInBase_400() {
        JsonNode base = json("{\"user_password\":\"hunter2\"}");
        assertThatThrownBy(() -> validator.validate(env(base, List.of(entry("rpi5", null)))))
                .satisfies(e -> assertThat(status(e)).isEqualTo(400));
    }

    @Test
    void plaintextSecretInImageSpec_400() {
        JsonNode spec = json("{\"role\":\"gateway\",\"luks_pass\":\"s3cret\"}");
        assertThatThrownBy(() -> validator.validate(env(null, List.of(entry("rpi5", spec)))))
                .satisfies(e -> assertThat(status(e)).isEqualTo(400));
    }

    @Test
    void blankSecretField_isAllowed() {
        // SECRET_FIELDS present-but-blank is the on-wire contract (from_dict blanks them).
        JsonNode base = json("{\"local_pass\":\"\",\"root_password\":\"\"}");
        assertThatCode(() -> validator.validate(env(base, List.of(entry("rpi5", null)))))
                .doesNotThrowAnyException();
    }

    @Test
    void nestedSecretInBaseUsers_400() {
        // A per-user password nested in base.users[] must be caught: the old shallow top-level
        // check missed it and the whole node was embedded verbatim into the build ConfigMap.
        JsonNode base = json("{\"brand\":\"brandx\",\"users\":[{\"username\":\"alice\","
                + "\"domain\":\"brandx.example\",\"user_password\":\"hunter2-PLAINTEXT\"}]}");
        assertThatThrownBy(() -> validator.validate(env(base, List.of(entry("rpi5", null)))))
                .isInstanceOf(ApiException.class)
                .satisfies(e -> assertThat(status(e)).isEqualTo(400));
    }

    @Test
    void nestedSecretInImageSpec_400() {
        // A secret nested inside an entry's imageSpec (accounts[].root_password) — the spec
        // subtree is persisted as image_spec_json and mounted, so it must be scanned at depth.
        JsonNode spec = json("{\"role\":\"gateway\",\"platform\":\"rpi5\","
                + "\"accounts\":[{\"name\":\"root\",\"root_password\":\"s3cret\"}]}");
        assertThatThrownBy(() -> validator.validate(env(null, List.of(entry("rpi5", spec)))))
                .satisfies(e -> assertThat(status(e)).isEqualTo(400));
    }

    @Test
    void blankNestedSecret_isAllowed() {
        // The recursion must NOT false-positive: a present-but-blank nested secret still passes.
        JsonNode base = json("{\"users\":[{\"username\":\"u\",\"user_password\":\"\"}]}");
        assertThatCode(() -> validator.validate(env(base, List.of(entry("rpi5", null)))))
                .doesNotThrowAnyException();
    }

    @Test
    void nestedSchemaInImageSpec_rejectedAsSmuggling_400() {
        JsonNode spec = json("{\"schema\":\"hugmesh-worklist/v1\",\"role\":\"x\"}");
        assertThatThrownBy(() -> validator.validate(env(null, List.of(entry("rpi5", spec)))))
                .satisfies(e -> assertThat(status(e)).isEqualTo(400));
    }

    @Test
    void badPackageAtom_400() {
        JsonNode spec = json("{\"packages_add\":\"not a valid atom!!\"}");
        assertThatThrownBy(() -> validator.validate(env(null, List.of(entry("rpi5", spec)))))
                .satisfies(e -> assertThat(status(e)).isEqualTo(400));
    }

    @Test
    void badDomainName_400() {
        JsonNode base = json("{\"domains\":[{\"name\":\"has spaces.example\"}]}");
        assertThatThrownBy(() -> validator.validate(env(base, List.of(entry("rpi5", null)))))
                .satisfies(e -> assertThat(status(e)).isEqualTo(400));
    }

    @Test
    void badSuperdomain_400() {
        JsonNode base = json("{\"superdomain\":\"bad_/domain\"}");
        assertThatThrownBy(() -> validator.validate(env(base, List.of(entry("rpi5", null)))))
                .satisfies(e -> assertThat(status(e)).isEqualTo(400));
    }
}
