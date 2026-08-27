package net.hugmesh.adminbff.optionalservices;

import org.junit.jupiter.api.Test;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * DRIFT GUARD for the vendored optional-services manifests that
 * {@link OptionalServiceRegistryParityTest} derives from. Those five files are VERBATIM copies
 * of {@code hugmesh-generator}'s {@code specs/cluster/...} (commit {@code 056a0e78}, main,
 * 2026-08-26); this test asserts the copies still match a generator checkout when one is
 * present, so an upstream slug addition/removal cannot pass unnoticed on a dev box.
 *
 * <p><b>Read this before trusting it.</b> Like the {@code ImageCatalogDriftTest} precedent it
 * follows, this test SKIPS when no generator checkout is found — and admin-bff's CI builds this
 * repo alone, so in CI it skips. That means:
 * <ul>
 *   <li>the PARITY check ({@link OptionalServiceRegistryParityTest}) always runs and is what
 *       actually gates the registry — it needs no generator checkout;</li>
 *   <li>a STALE vendored fixture is a real residual risk this test only covers locally. The
 *       durable fix is a generator-side check that fails when its own manifests move without
 *       this repo's fixtures moving; that is cross-repo work and is NOT done here.</li>
 * </ul>
 * Point it at a checkout with {@code -Doptionalservices.source.dir=<generator>/specs/cluster}
 * (the pom forwards the property to the forked test JVM).
 */
class OptionalServiceManifestDriftTest {

    /** Vendored classpath resource -> its path under the generator's {@code specs/cluster}. */
    private static final String[][] FIXTURES = {
            {"/optionalservices/crd-optionalservice.yaml",
                    "manifests/optional-services-operator/crd-optionalservice.yaml"},
            {"/optionalservices/seed-optionalservices.yaml",
                    "manifests/optional-services-operator/seed-optionalservices.yaml"},
            {"/optionalservices/13a-optional-services.yaml",
                    "apps/13a-optional-services.yaml"},
            {"/optionalservices/16-reserved-prefixes-policy.yaml",
                    "apps/16-reserved-prefixes-policy.yaml"},
            {"/optionalservices/installed-services-configmap.yaml",
                    "manifests/policy/installed-services-configmap.yaml"},
    };

    private static Path sourceDir() {
        return Path.of(System.getProperty("optionalservices.source.dir",
                "../hugmesh-generator/specs/cluster"));
    }

    @Test
    void vendoredOptionalServiceManifests_matchGeneratorSource() throws Exception {
        Path dir = sourceDir();
        assumeTrue(Files.isDirectory(dir),
                "generator checkout not present (" + dir.toAbsolutePath()
                        + ") — the vendored fixtures are authoritative here and the PARITY test "
                        + "still gates the registry");

        for (String[] fixture : FIXTURES) {
            Path source = dir.resolve(fixture[1]);
            assumeTrue(Files.isRegularFile(source), "generator source not present: " + source);
            assertEquals(Files.readString(source, StandardCharsets.UTF_8), vendored(fixture[0]),
                    "vendored " + fixture[0] + " has DRIFTED from the generator source " + source
                            + " — re-copy it AND re-check the OptionalServiceRegistry "
                            + "classification it pins (never hand-edit the vendored copy)");
        }
    }

    private static String vendored(String resource) throws Exception {
        try (InputStream in = OptionalServiceManifestDriftTest.class.getResourceAsStream(resource)) {
            if (in == null) {
                throw new IllegalStateException("vendored fixture " + resource + " is MISSING");
            }
            return new String(in.readAllBytes(), StandardCharsets.UTF_8);
        }
    }
}
