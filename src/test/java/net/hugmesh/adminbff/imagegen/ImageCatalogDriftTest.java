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
 * CI DRIFT GUARD: the two catalogs the BFF serves are a VENDORED copy of the generator's
 * canonical source of truth ({@code redesign/docs/catalog/{packages-catalog.json,
 * image-catalog.json}}, emitted by {@code scripts/emit-{package,image}-catalog.py}). This test
 * asserts the vendored classpath copy is byte-for-byte semantically identical to the generator
 * source, so a stale hand-edit or an un-refreshed generator change fails the build instead of
 * silently serving a drifted catalog to the wizard. It is the assertive half of the design
 * decision "build-time COPY task + CI drift test; never hand-vendor a stale snapshot".
 *
 * <p>The generator checkout is located via {@code -Dcatalog.source.dir=<dir>} (the pom's
 * {@code catalog-copy} profile passes the same directory it refreshes from), defaulting to the
 * sandbox redesign checkout. When the generator source is NOT present (e.g. a downstream CI that
 * builds the BFF alone), the test SKIPS rather than fails — the vendored copy is authoritative
 * there and its presence/parse is already covered by {@link ImageCatalogControllerTest}.
 */
class ImageCatalogDriftTest {

    /** Overridable generator catalog dir; default = the sandbox generator (read-only) checkout. */
    private static final String DEFAULT_SOURCE_DIR =
            "/var/tmp/portage/hugmesh-work/redesign/docs/catalog";

    // Jackson 3 (tools.jackson) — the same tree type ImageCatalogProvider serves, so the drift
    // check compares like-for-like with the WebFlux codec path.
    private final ObjectMapper mapper = JsonMapper.builder().build();

    private static Path sourceDir() {
        return Path.of(System.getProperty("catalog.source.dir", DEFAULT_SOURCE_DIR));
    }

    @Test
    void vendoredPackagesCatalog_matchesGeneratorSource() throws IOException {
        assertNoDrift(ImageCatalogProvider.PACKAGES_RESOURCE, "packages-catalog.json");
    }

    @Test
    void vendoredImageCatalog_matchesGeneratorSource() throws IOException {
        assertNoDrift(ImageCatalogProvider.IMAGES_RESOURCE, "image-catalog.json");
    }

    private void assertNoDrift(String classpathResource, String sourceFileName) throws IOException {
        Path source = sourceDir().resolve(sourceFileName);
        assumeTrue(Files.isRegularFile(source),
                "generator source not present (" + source + ") — vendored copy is authoritative here");

        JsonNode vendored;
        try (InputStream in = new ClassPathResource(classpathResource).getInputStream()) {
            vendored = mapper.readTree(in);
        }
        JsonNode generator = mapper.readTree(source);

        assertEquals(generator, vendored,
                "vendored " + classpathResource + " has DRIFTED from the generator source "
                        + source + " — re-run the build with the catalog-copy profile to refresh "
                        + "(never hand-edit the vendored copy)");
    }
}
