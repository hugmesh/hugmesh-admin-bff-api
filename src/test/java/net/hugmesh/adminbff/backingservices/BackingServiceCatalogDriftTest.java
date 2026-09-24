package net.hugmesh.adminbff.backingservices;

import org.junit.jupiter.api.Test;
import org.yaml.snakeyaml.Yaml;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.fail;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * DRIFT GUARD between {@link BackingServiceCatalog} and the generator's backing-service registry,
 * {@code hugmesh-generator/specs/cluster/backing-services.yaml} ({@code kind:
 * BackingServiceRegistry}). The ids must be ONE namespace: an id this catalog accepts is written
 * to {@code backing_service_mode.service_id} and is meant to be the key the generator's builder
 * ({@code gate_backing_services()}, {@code _MGD_TIER12_IDS} / {@code _MGD_TIER3_IDS}) and the
 * ConfigMap contract (decision 13, hugmesh-admin-bff-api#9) read back. Before
 * hugmesh-admin-bff-api#58 (decision 92 = A) this catalog said {@code object-store} where both
 * generator authorities said {@code velero-objectstore}, and nothing on either side noticed.
 *
 * <p><b>Which registry it reads, in order</b> (the resolved source is printed and named in every
 * failure message):
 * <ol>
 *   <li>a LIVE generator checkout, when {@code -Dbackingservices.source.dir=<generator>/specs/cluster}
 *       or the environment variable {@code BACKINGSERVICES_SOURCE_DIR} is set. An explicit pointer
 *       that does not hold a {@code backing-services.yaml} FAILS — a typo must never quietly fall
 *       back to the vendored copy;</li>
 *   <li>otherwise the VENDORED copy {@code src/test/resources/backing-services.yaml}, a verbatim
 *       copy of the generator file at {@link #VENDORED_FROM_SHA} (byte-identical to generator
 *       {@code main} at {@code b5901697}, 2026-09-23). This is the leg that runs in this repo's
 *       CI, which builds admin-bff alone;</li>
 *   <li>neither: every test here is SKIPPED with a loud reason (JUnit assumption), never passed.</li>
 * </ol>
 *
 * <p><b>The builder's accepted list is pinned transitively, not here.</b> The generator's own
 * {@code tests/managed-services/test-managed-services-gate.sh} asserts the YAML registry's id set
 * equals the builder's {@code _MGD_TIER12_IDS} / {@code _MGD_TIER3_IDS}; this test pins the YAML
 * to the Java catalog. Parsing a shell array out of a 2000-line build script from a Java test
 * would be a second copy of that gate that rots on the first reformat.
 *
 * <p><b>Deliberately NOT compared: {@code kind}.</b> The two sides use different KIND
 * vocabularies ({@code object-storage} here, {@code object-store} in the registry, for both
 * {@code velero-objectstore} and {@code federation-bundles}). Decision 92 ruled on the id only;
 * pinning kinds would be a second, unruled decision disguised as a test.
 *
 * <p><b>Refreshing the vendored copy.</b> Re-copy it VERBATIM ({@code git show
 * <sha>:specs/cluster/backing-services.yaml}) and update {@link #VENDORED_FROM_SHA}; never
 * hand-edit it. Running with {@code -Dbackingservices.source.dir} additionally fails when the
 * vendored bytes differ from the checkout's, so a stale copy surfaces on any dev box that has
 * the generator beside it.
 */
class BackingServiceCatalogDriftTest {

    /** The generator commit the vendored {@code backing-services.yaml} was copied from. */
    static final String VENDORED_FROM_SHA = "c846c83b2d2bc02090635ec38abba37cbbe2c5e9";

    private static final String VENDORED_RESOURCE = "/backing-services.yaml";
    private static final String REGISTRY_FILE = "backing-services.yaml";

    /** A resolved registry: where it came from (for messages) and its text. */
    record Source(String description, String text) {
    }

    /** The explicit live-checkout pointer, or null when neither the property nor the env is set. */
    static String explicitSourceDir() {
        String dir = System.getProperty("backingservices.source.dir");
        if (dir == null || dir.isBlank()) {
            dir = System.getenv("BACKINGSERVICES_SOURCE_DIR");
        }
        return (dir == null || dir.isBlank()) ? null : dir.trim();
    }

    static String vendoredText() throws IOException {
        try (InputStream in = BackingServiceCatalogDriftTest.class.getResourceAsStream(VENDORED_RESOURCE)) {
            return in == null ? null : new String(in.readAllBytes(), StandardCharsets.UTF_8);
        }
    }

    /**
     * Resolve the registry per the class javadoc. Returns only when a source exists; otherwise the
     * calling test is SKIPPED (explicit pointer that resolves nothing = FAIL, not skip).
     */
    static Source resolve() throws IOException {
        String dir = explicitSourceDir();
        if (dir != null) {
            Path file = Path.of(dir).resolve(REGISTRY_FILE);
            if (!Files.isRegularFile(file)) {
                fail("backingservices.source.dir / BACKINGSERVICES_SOURCE_DIR is set to '" + dir
                        + "' but " + file.toAbsolutePath() + " does not exist — refusing to fall back "
                        + "to the vendored copy behind an explicit pointer");
            }
            Source live = new Source("LIVE " + file.toAbsolutePath(),
                    Files.readString(file, StandardCharsets.UTF_8));
            System.out.println("[backing-service drift] registry source: " + live.description());
            return live;
        }
        String vendored = vendoredText();
        assumeTrue(vendored != null,
                "BACKING-SERVICE DRIFT GUARD SKIPPED — NOT PASSED: no registry to compare against. "
                        + "Neither -Dbackingservices.source.dir / BACKINGSERVICES_SOURCE_DIR nor the "
                        + "vendored src/test/resources/backing-services.yaml exists, so "
                        + "BackingServiceCatalog ids are UNGUARDED against the generator registry.");
        Source src = new Source("VENDORED classpath:" + VENDORED_RESOURCE + " (generator@"
                + VENDORED_FROM_SHA.substring(0, 8) + ")", vendored);
        System.out.println("[backing-service drift] registry source: " + src.description());
        return src;
    }

    /** id -> the registry's service map, in file order. Fails (never empties) on a reshaped file. */
    @SuppressWarnings("unchecked")
    static Map<String, Map<String, Object>> registryServices(Source src) {
        Object doc = new Yaml().load(src.text());
        if (!(doc instanceof Map<?, ?> root)
                || !"BackingServiceRegistry".equals(root.get("kind"))
                || !(root.get("spec") instanceof Map<?, ?> spec)
                || !(spec.get("services") instanceof List<?> services)
                || services.isEmpty()) {
            fail(src.description() + " is not a non-empty kind: BackingServiceRegistry with "
                    + "spec.services[] — the guard cannot read it, so it refuses to pass");
            return Map.of();
        }
        Map<String, Map<String, Object>> byId = new LinkedHashMap<>();
        for (Object o : services) {
            if (!(o instanceof Map<?, ?> svc) || !(svc.get("id") instanceof String id) || id.isBlank()) {
                fail(src.description() + " has a spec.services[] entry without a string id: " + o);
                return Map.of();
            }
            if (byId.put(id, (Map<String, Object>) svc) != null) {
                fail(src.description() + " declares the id '" + id + "' twice");
            }
        }
        return byId;
    }

    @Test
    void catalogIds_equalGeneratorRegistryIds_inBothDirections() throws IOException {
        Source src = resolve();
        Set<String> registry = new TreeSet<>(registryServices(src).keySet());
        Set<String> catalog = new TreeSet<>(BackingServiceCatalog.ids());

        Set<String> onlyInCatalog = new TreeSet<>(catalog);
        onlyInCatalog.removeAll(registry);
        Set<String> onlyInRegistry = new TreeSet<>(registry);
        onlyInRegistry.removeAll(catalog);

        assertThat(onlyInCatalog.isEmpty() && onlyInRegistry.isEmpty())
                .as("backing-service id namespaces have DRIFTED (hugmesh-admin-bff-api#58). "
                        + "Only in BackingServiceCatalog: " + onlyInCatalog
                        + " — a superadmin can record these but the generator builder dies on them "
                        + "('unknown backing-service id'). Only in the registry (" + src.description()
                        + "): " + onlyInRegistry + " — the builder accepts these but the admin plane "
                        + "cannot record them. Fix the side that is wrong; never add an alias.")
                .isTrue();
        // Non-vacuity: the catalog is the 15-row closed set, and equality above means the registry is too.
        assertThat(catalog).as("BackingServiceCatalog.ids() is suspiciously small").hasSizeGreaterThanOrEqualTo(15);
    }

    @Test
    void catalogTiers_andDocsOnly_matchGeneratorRegistry() throws IOException {
        Source src = resolve();
        Map<String, Map<String, Object>> registry = registryServices(src);
        StringBuilder drift = new StringBuilder();
        int compared = 0;
        for (BackingServiceCatalog.BackingService svc : BackingServiceCatalog.SERVICES) {
            Map<String, Object> row = registry.get(svc.id());
            if (row == null) {
                continue; // the id test above owns id drift; do not double-report it here
            }
            compared++;
            Object tier = row.get("tier");
            Object docsOnly = row.get("docsOnly");
            if (!(tier instanceof Integer t) || t != svc.tier()) {
                drift.append("\n  ").append(svc.id()).append(": catalog tier ").append(svc.tier())
                        .append(", registry tier ").append(tier);
            }
            if (!(docsOnly instanceof Boolean d) || d != svc.docsOnly()) {
                drift.append("\n  ").append(svc.id()).append(": catalog docsOnly ").append(svc.docsOnly())
                        .append(", registry docsOnly ").append(docsOnly);
            }
        }
        assertThat(drift.toString())
                .as("tier / docsOnly drift between BackingServiceCatalog and " + src.description()
                        + " — the admin plane would accept a mode change the builder refuses (or the "
                        + "reverse):")
                .isEmpty();
        assertThat(compared).as("no catalog row matched the registry, so nothing was compared")
                .isPositive();
    }

    @Test
    void vendoredRegistry_isByteIdenticalToTheLiveCheckout_whenOneIsGiven() throws IOException {
        String dir = explicitSourceDir();
        assumeTrue(dir != null,
                "no -Dbackingservices.source.dir / BACKINGSERVICES_SOURCE_DIR — the vendored copy "
                        + "(generator@" + VENDORED_FROM_SHA.substring(0, 8) + ") cannot be checked "
                        + "for staleness in this run; the id/tier guards above ran on it instead");
        Source live = resolve();
        String vendored = vendoredText();
        assertThat(vendored)
                .as("vendored src/test/resources/backing-services.yaml is MISSING").isNotNull();
        assertThat(vendored)
                .as("vendored backing-services.yaml (generator@" + VENDORED_FROM_SHA.substring(0, 8)
                        + ") has DRIFTED from " + live.description() + " — re-copy it verbatim, bump "
                        + "VENDORED_FROM_SHA, and re-run the id/tier guards (never hand-edit it)")
                .isEqualTo(live.text());
    }
}
