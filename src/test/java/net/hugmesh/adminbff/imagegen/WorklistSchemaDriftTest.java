package net.hugmesh.adminbff.imagegen;

import org.junit.jupiter.api.Test;
import org.springframework.core.io.ClassPathResource;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * CI DRIFT GUARD for the vendored generator worklist schema
 * ({@value GeneratorPlatforms#SCHEMA_RESOURCE}), the source of the platform set the batch
 * image-build channel accepts. The generator owns {@code docs/schemas/worklist.v1.schema.json};
 * this test asserts the vendored copy still matches it, so a platform the generator adds fails
 * this build until the copy is refreshed, instead of being refused by the web admin channel.
 *
 * <p>The source is found next to the generator catalogs: {@code <catalog.source.dir>/../schemas}
 * ({@code catalog.source.dir} is the generator's {@code docs/catalog}, which CI already passes for
 * {@link ImageCatalogDriftTest}). Like that test it SKIPS when no generator checkout is present;
 * CI's preflight asserts the file by name so a failed checkout cannot pass as a skip. Refresh by
 * copying the generator file over {@code src/main/resources/schema/worklist.v1.schema.json};
 * never hand-edit the vendored copy, and this test never rewrites it.
 */
class WorklistSchemaDriftTest {

    private static final String DEFAULT_CATALOG_DIR =
            "/var/tmp/portage/hugmesh-work/redesign/docs/catalog";

    private final ObjectMapper mapper = JsonMapper.builder().build();

    static Path sourceFile() {
        Path catalog = Path.of(System.getProperty("catalog.source.dir", DEFAULT_CATALOG_DIR));
        return catalog.resolveSibling("schemas").resolve("worklist.v1.schema.json");
    }

    @Test
    void vendoredWorklistSchema_matchesGeneratorSource() throws IOException {
        Path source = sourceFile();
        assumeTrue(Files.isRegularFile(source),
                "generator source not present (" + source + ") — vendored copy is authoritative here");

        JsonNode vendored;
        try (InputStream in = new ClassPathResource(GeneratorPlatforms.SCHEMA_RESOURCE).getInputStream()) {
            vendored = mapper.readTree(in);
        }
        JsonNode generator = mapper.readTree(source);

        assertEquals(generator, vendored,
                "vendored " + GeneratorPlatforms.SCHEMA_RESOURCE + " has DRIFTED from the generator "
                        + "source " + source + " — copy the generator file over "
                        + "src/main/resources/" + GeneratorPlatforms.SCHEMA_RESOURCE
                        + " and commit (never hand-edit the vendored copy)");
    }
}
