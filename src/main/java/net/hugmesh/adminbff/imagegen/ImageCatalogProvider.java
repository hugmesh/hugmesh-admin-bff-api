package net.hugmesh.adminbff.imagegen;

import org.springframework.core.io.ClassPathResource;
import org.springframework.stereotype.Component;
import tools.jackson.core.JacksonException;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;

import java.io.IOException;
import java.io.InputStream;

/**
 * Loads the generator's role×platform + package-tree catalogs from the classpath ONCE at
 * startup and exposes them as parsed {@link JsonNode} trees for pass-through serving by
 * {@link ImageCatalogController}.
 *
 * <p><b>Vendored, not hand-authored.</b> The two JSONs under {@code resources/catalog/} are a
 * build-time COPY of the generator's canonical source of truth
 * ({@code redesign/docs/catalog/{packages-catalog.json,image-catalog.json}}, themselves emitted
 * by {@code scripts/emit-{package,image}-catalog.py}). The pom's {@code catalog-copy} profile
 * refreshes the vendored copy from the generator checkout at {@code generate-resources}; the
 * {@link ImageCatalogDriftTest} fails the build if the vendored copy ever drifts from the
 * generator source. This mirrors the design decision "never hand-vendor a stale snapshot".
 *
 * <p><b>Read verbatim.</b> The trees are served pass-through — the UI (and the Studio GUI) read
 * the SAME shapes: {@code image-catalog.json} = {@code platform_labels} + {@code role_class}
 * ({@code desktop[]}/{@code node[]}) + {@code roles.<mode>[]}; {@code packages-catalog.json} =
 * {@code adhoc_adds{key:{atoms[],label}}} + {@code platforms.<plat>.packages.sections[].atoms}.
 * The gating PREDICATES / essential-floor / live tier split are NOT in these JSONs (they live in
 * the generator's {@code package_catalog.py}); live tier-resolution is deferred/structural.
 *
 * <p>Fail-fast: a missing or malformed classpath resource throws at construction (mirrors
 * {@link ImageBuildOrchestrator#renderManifest} refusing to boot on a missing job template),
 * so the console never serves a half-broken catalog.
 */
@Component
public class ImageCatalogProvider {

    /** Classpath location of the vendored package/service tree catalog. */
    public static final String PACKAGES_RESOURCE = "catalog/packages-catalog.json";
    /** Classpath location of the vendored role×platform image catalog. */
    public static final String IMAGES_RESOURCE = "catalog/image-catalog.json";

    private final JsonNode packages;
    private final JsonNode images;

    public ImageCatalogProvider() {
        // Boot 4 promoted Jackson 3 (tools.jackson) to the WebFlux JSON codec. The served trees
        // MUST be Jackson-3 JsonNodes so the reactive encoder introspects + inlines them (a
        // Jackson-2 com.fasterxml JsonNode would be serialised opaquely, NOT as nested JSON).
        ObjectMapper mapper = JsonMapper.builder().build();
        this.packages = load(mapper, PACKAGES_RESOURCE);
        this.images = load(mapper, IMAGES_RESOURCE);
    }

    private static JsonNode load(ObjectMapper mapper, String resource) {
        ClassPathResource cp = new ClassPathResource(resource);
        try (InputStream in = cp.getInputStream()) {
            JsonNode node = mapper.readTree(in);
            if (node == null || node.isMissingNode() || !node.isObject()) {
                throw new IllegalStateException(
                        "image-gen catalog resource is not a JSON object: " + resource);
            }
            return node;
        } catch (IOException | JacksonException e) {
            throw new IllegalStateException(
                    "image-gen catalog resource missing/unreadable/malformed: " + resource, e);
        }
    }

    /** The package/service tree catalog ({@code adhoc_adds} + {@code platforms}). */
    public JsonNode packages() {
        return packages;
    }

    /** The role×platform image catalog ({@code platform_labels} + {@code role_class} + {@code roles}). */
    public JsonNode images() {
        return images;
    }
}
