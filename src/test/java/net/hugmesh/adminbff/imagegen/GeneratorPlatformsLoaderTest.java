package net.hugmesh.adminbff.imagegen;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.io.IOException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * {@link GeneratorPlatforms} fails CLOSED on a schema it cannot trust: the BFF must not start
 * with an empty, missing or widened platform set. Each case feeds {@code readEnum} a crafted
 * schema tree; the vendored file itself is covered by {@link GeneratorPlatformsContractTest}.
 */
class GeneratorPlatformsLoaderTest {

    private static final ObjectMapper M = new ObjectMapper();

    private static JsonNode schemaWithEntryEnum(String enumJson) throws IOException {
        return M.readTree("{\"$defs\":{\"worklistEntry\":{\"properties\":{\"platform\":"
                + "{\"type\":\"string\",\"enum\":" + enumJson + "}}}}}");
    }

    @Test
    void wellFormedEnum_isReadInSchemaOrder() throws IOException {
        assertThat(GeneratorPlatforms.readEnum(schemaWithEntryEnum("[\"x86\",\"orangepi3-lts\",\"rpi5\"]"),
                "worklistEntry")).containsExactly("x86", "orangepi3-lts", "rpi5");
    }

    @Test
    void eachFieldReadsItsOwnDefinition() throws IOException {
        // The two enums are identical in today's schema; make them differ so a loader that read
        // one definition for both fields cannot pass.
        JsonNode schema = M.readTree("{\"$defs\":{"
                + "\"worklistEntry\":{\"properties\":{\"platform\":{\"enum\":[\"x86\",\"rpi5\"]}}},"
                + "\"imageConfig\":{\"properties\":{\"platform\":{\"enum\":[\"x86\",\"frite\"]}}}}}");
        GeneratorPlatforms.Sets sets = GeneratorPlatforms.read(schema);
        assertThat(sets.entry()).containsExactly("x86", "rpi5");
        assertThat(sets.imageSpec()).containsExactly("x86", "frite");
    }

    @Test
    void missingImageConfigDefinition_failsClosed() throws IOException {
        assertThatThrownBy(() -> GeneratorPlatforms.read(schemaWithEntryEnum("[\"x86\"]")))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("$defs.imageConfig.properties.platform.enum is missing or empty");
    }

    @Test
    void missingDefinition_failsClosed() throws IOException {
        assertThatThrownBy(() -> GeneratorPlatforms.readEnum(M.readTree("{}"), "worklistEntry"))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("$defs.worklistEntry.properties.platform.enum is missing or empty");
    }

    @Test
    void enumNotAnArray_failsClosed() throws IOException {
        assertThatThrownBy(() -> GeneratorPlatforms.readEnum(schemaWithEntryEnum("\"x86\""), "worklistEntry"))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("is missing or empty");
    }

    @Test
    void emptyEnum_failsClosed() throws IOException {
        assertThatThrownBy(() -> GeneratorPlatforms.readEnum(schemaWithEntryEnum("[]"), "worklistEntry"))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("is missing or empty");
    }

    @ParameterizedTest(name = "enum member {0} fails closed")
    @ValueSource(strings = {"7", "null", "\"\"", "\"X86\"", "\"x86|rpi5\"", "\"rpi5\\n\"",
            "\"rpi5\\\"\"", "\"-x86\"", "\"x86-\"", "\"a b\"", "\"../x\"", "\"${x}\"",
            "\"abcdefghijklmnopqrstuvwxyz0123456\""})
    void untrustedMember_failsClosed(String member) throws IOException {
        assertThatThrownBy(() -> GeneratorPlatforms.readEnum(
                schemaWithEntryEnum("[\"x86\"," + member + "]"), "worklistEntry"))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("is not a platform token");
    }
}
