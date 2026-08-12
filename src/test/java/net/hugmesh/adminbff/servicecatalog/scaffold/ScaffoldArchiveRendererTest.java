package net.hugmesh.adminbff.servicecatalog.scaffold;

import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The scaffold ARCHIVE round-trip over the REAL embedded skeletons (classpath
 * {@code scaffold/<archetype>/**}, no Spring / no Docker). Proves, per archetype, that the render:
 * <ul>
 *   <li>emits the expected starter files;</li>
 *   <li>substitutes every {@code {{TOKEN}}} — ZERO {@code {{UPPER_SNAKE}}} residual + no
 *       {@code {{!}}} separator survives (the render hard-fails on a residual, so a green render
 *       is itself the proof; the assertions document + lock it);</li>
 *   <li>relocates the spring-bff Java sources into the real package path (net/hugmesh/&lt;slug&gt;);</li>
 *   <li>renders NO secret material (no PEM private-key block).</li>
 * </ul>
 */
class ScaffoldArchiveRendererTest {

    private static final ScaffoldArchiveRenderer RENDERER = new ScaffoldArchiveRenderer();
    private static final ScaffoldRenderContext CONTEXT = new ScaffoldRenderContext(
            "hugmesh", "", "hugmesh", "mesh_default", "hugmesh",
            "http://headscale.headscale.svc.cluster.local:8080", "prod");

    private Map<String, String> renderAndUnzip(String archetype, String serviceKey) {
        Map<String, String> ctx = CONTEXT.build("acme.test", serviceKey, "Owncast");
        boolean relocate = ScaffoldCatalog.requiresJavaPackageSafeSlug(archetype);
        byte[] zip = RENDERER.render(archetype, ScaffoldRenderContext.appSlug(serviceKey), relocate, ctx);
        return unzip(zip);
    }

    private static Map<String, String> unzip(byte[] zip) {
        Map<String, String> out = new LinkedHashMap<>();
        try (ZipInputStream zis = new ZipInputStream(new ByteArrayInputStream(zip))) {
            ZipEntry e;
            while ((e = zis.getNextEntry()) != null) {
                out.put(e.getName(), new String(zis.readAllBytes(), StandardCharsets.UTF_8));
            }
        } catch (IOException ex) {
            throw new AssertionError("failed to unzip rendered archive", ex);
        }
        return out;
    }

    /** Every rendered file must be fully substituted + carry no secret + no leftover separator. */
    private static void assertFullyRenderedAndSecretFree(Map<String, String> files) {
        assertThat(files).isNotEmpty();
        files.forEach((name, content) -> {
            assertThat(TokenRenderer.residualTokens(content))
                    .as("rendered file %s has no {{UPPER_SNAKE}} residual", name).isEmpty();
            assertThat(content).as("rendered file %s has no {{!}} separator left", name)
                    .doesNotContain("{{!}}");
            assertThat(content).as("rendered file %s ships no PEM private key", name)
                    .doesNotContain("-----BEGIN");
        });
    }

    @Test
    void springBff_rendersRunnableTree_withRelocatedJavaPackage() {
        Map<String, String> files = renderAndUnzip("spring-bff", "owncast");
        assertFullyRenderedAndSecretFree(files);

        // The Java sources are relocated from the neutral app/ dir into the real package path.
        assertThat(files).containsKey("pom.xml")
                .containsKey("src/main/java/net/hugmesh/owncast/Application.java")
                .containsKey("src/main/java/net/hugmesh/owncast/HelloController.java")
                .containsKey("src/main/resources/application.yml");
        assertThat(files.keySet()).noneMatch(k -> k.contains("net/hugmesh/app/"));

        // The declared package matches the relocated directory (a conventional, runnable tree).
        assertThat(files.get("src/main/java/net/hugmesh/owncast/Application.java"))
                .contains("package net.hugmesh.owncast;")
                .doesNotContain("{{");
        assertThat(files.get("pom.xml")).contains("<artifactId>owncast-bff</artifactId>");
        // The ${ENV:default} identity + the {{!}}-separated default rendered cleanly.
        assertThat(files.get("src/main/resources/application.yml"))
                .contains("name: \"owncast-bff\"")
                .contains("https://id.acme.test")
                .doesNotContain("{{");
    }

    @Test
    void springBff_hyphenSafeSlugIsUnaffected_butRendererRelocatesWhateverSlugIsGiven() {
        // The service layer rejects a hyphenated slug for spring-bff BEFORE this runs; the renderer
        // itself relocates to whatever appSlug it is handed (here a clean alnum slug).
        Map<String, String> files = renderAndUnzip("spring-bff", "owncast");
        assertThat(files).containsKey("src/test/java/net/hugmesh/owncast/HelloControllerTest.java");
    }

    @Test
    void angularMfe_rendersRemote_withValidNpmScopedName() {
        Map<String, String> files = renderAndUnzip("angular-mfe", "owncast");
        assertFullyRenderedAndSecretFree(files);

        assertThat(files).containsKey("package.json").containsKey("federation.config.js")
                .containsKey("src/app/remote.routes.ts");
        // NPM_SCOPE = slug(org) = "hugmesh" (BARE — the skeleton prepends the literal '@'),
        // APP_SLUG = "owncast": a VALID @scope/name (the impl-note "@+domainSlug" would double '@').
        assertThat(files.get("package.json")).contains("\"@hugmesh/owncast\"")
                .doesNotContain("@@");
    }

    @Test
    void angularHost_rendersHostShell_withHostNameScopedName() {
        Map<String, String> files = renderAndUnzip("angular-host", "owncast");
        assertFullyRenderedAndSecretFree(files);

        assertThat(files).containsKey("package.json")
                .containsKey("src/assets/federation.manifest.json")
                .containsKey("federation.config.js");
        // HOST_NAME = slug(domain) + "-host" = "acme-test-host".
        assertThat(files.get("package.json")).contains("\"@hugmesh/acme-test-host\"");
        assertThat(files.get("federation.config.js")).contains("acme-test-host");
    }

    @Test
    void remoteFragment_rendersPointerReadme() {
        Map<String, String> files = renderAndUnzip("remote-fragment", "owncast");
        assertFullyRenderedAndSecretFree(files);
        assertThat(files).containsOnlyKeys("README.md");
        assertThat(files.get("README.md")).contains("Owncast").contains("hugmesh-owncast");
    }

    @Test
    void gitlabCiIncludeRendersAsGroupSlashProjectPath() {
        // GENERATOR_ORG_GROUP must be the CI-include <group>/<project> path (a bare group is an
        // invalid `project:` include). Derived: slug(org) + "/hugmesh-generator".
        Map<String, String> files = renderAndUnzip("spring-bff", "owncast");
        assertThat(files.get(".gitlab-ci.yml")).contains("project: 'hugmesh/hugmesh-generator'");
    }
}
