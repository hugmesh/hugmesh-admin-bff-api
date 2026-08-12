package net.hugmesh.adminbff.servicecatalog.scaffold;

import org.springframework.core.io.Resource;
import org.springframework.core.io.support.PathMatchingResourcePatternResolver;
import org.springframework.core.io.support.ResourcePatternResolver;
import org.springframework.stereotype.Component;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

/**
 * Renders a vendored scaffold skeleton tree (classpath {@code scaffold/<archetype>/**}) into a
 * ZIP of the STARTER codebase, substituting the {@code {{TOKEN}}}s via {@link TokenRenderer}.
 *
 * <h3>Package relocation (spring-bff)</h3>
 * The generator keeps a spring-bff skeleton's Java sources under the neutral directory
 * {@code src/main/java/net/hugmesh/app/} while the source files DECLARE the real package
 * {@code net.hugmesh.<APP_SLUG>} (its renderer substitutes CONTENT only, never paths).
 * A hand-off ZIP should be immediately conventional, so for the Java-package archetypes this
 * renderer RELOCATES those entries into {@code net/hugmesh/<slug>/} so the on-disk path
 * matches the declared package (no post-adoption {@code git mv} needed).
 *
 * <h3>Blocking — call off the event loop</h3>
 * Enumerating + reading classpath resources and zipping are BLOCKING; {@link #render} is a plain
 * synchronous method and the controller invokes it on {@code Schedulers.boundedElastic}. Zip
 * entries are written with a fixed timestamp so a re-render of the same inputs is byte-stable.
 */
@Component
public class ScaffoldArchiveRenderer {

    /** The neutral package directory the generator parks spring-bff Java sources under. */
    private static final String NEUTRAL_PKG = "net/hugmesh/app/";
    /** Fixed zip-entry mtime (2020-01-01Z) so identical inputs render byte-identically. */
    private static final long FIXED_TIME = 1577836800000L;

    private final ResourcePatternResolver resolver;

    public ScaffoldArchiveRenderer() {
        this(new PathMatchingResourcePatternResolver());
    }

    /** Test seam — inject a resolver bound to a specific classloader. */
    ScaffoldArchiveRenderer(ResourcePatternResolver resolver) {
        this.resolver = resolver;
    }

    /**
     * The rendered starter codebase for {@code archetype} as ZIP bytes. {@code context} MUST carry
     * every token the skeletons use (a residual {@code {{UPPER_SNAKE}}} hard-fails via
     * {@link TokenRenderer}). {@code appSlug} is the rendered {@code APP_SLUG} used for the Java
     * package relocation; {@code relocateJavaPackage} gates that relocation to the archetypes whose
     * slug feeds a package.
     *
     * @throws IllegalStateException if the archetype tree is empty (no vendored resources found)
     * @throws UncheckedIOException  on a classpath read / zip failure
     */
    public byte[] render(String archetype, String appSlug, boolean relocateJavaPackage,
                         Map<String, String> context) {
        Map<String, Resource> entries = loadTree(archetype);
        if (entries.isEmpty()) {
            throw new IllegalStateException(
                    "scaffold archetype '" + archetype + "' has no vendored resources on the classpath");
        }
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        try (ZipOutputStream zip = new ZipOutputStream(buf)) {
            for (Map.Entry<String, Resource> e : entries.entrySet()) {
                String entryName = relocateJavaPackage
                        ? e.getKey().replace(NEUTRAL_PKG, "net/hugmesh/" + appSlug + "/")
                        : e.getKey();
                String rendered = TokenRenderer.render(readUtf8(e.getValue()), context);
                ZipEntry ze = new ZipEntry(entryName);
                ze.setTime(FIXED_TIME);
                zip.putNextEntry(ze);
                zip.write(rendered.getBytes(StandardCharsets.UTF_8));
                zip.closeEntry();
            }
        } catch (IOException ex) {
            throw new UncheckedIOException("failed to render scaffold archive for '" + archetype + "'", ex);
        }
        return buf.toByteArray();
    }

    /** The sorted relative file paths vendored for {@code archetype} (the render/adopt file set;
     *  package-visible for the render tests). */
    List<String> relativePaths(String archetype) {
        return new ArrayList<>(loadTree(archetype).keySet());
    }

    /** The vendored file resources of {@code archetype} keyed by their tree-relative path, sorted
     *  (deterministic zip order). Directory entries are skipped. */
    private Map<String, Resource> loadTree(String archetype) {
        String base = "scaffold/" + archetype + "/";
        Map<String, Resource> out = new TreeMap<>();
        Resource[] found;
        try {
            found = resolver.getResources("classpath*:" + base + "**");
        } catch (IOException ex) {
            throw new UncheckedIOException("failed to enumerate scaffold resources for '" + archetype + "'", ex);
        }
        for (Resource r : found) {
            String rel = relativePath(r, base);
            if (rel == null || rel.isEmpty() || rel.endsWith("/") || isDirectory(r)) {
                continue;
            }
            out.put(rel, r);
        }
        return out;
    }

    /** The path of {@code r} relative to {@code base} (the {@code scaffold/<archetype>/} root),
     *  computed from its URI so it is correct for both exploded-classpath and in-jar layouts. */
    private static String relativePath(Resource r, String base) {
        URI uri;
        try {
            uri = r.getURI();
        } catch (IOException ex) {
            return null;
        }
        String s = uri.toString();
        int idx = s.indexOf(base);
        return idx < 0 ? null : s.substring(idx + base.length());
    }

    /** True when {@code r} is a filesystem DIRECTORY (jar dir entries end with '/' and are already
     *  filtered by the caller). Any non-filesystem resource is treated as a file. */
    private static boolean isDirectory(Resource r) {
        try {
            return "file".equals(r.getURI().getScheme()) && r.getFile().isDirectory();
        } catch (IOException ex) {
            return false;
        }
    }

    private static String readUtf8(Resource r) {
        try (InputStream in = r.getInputStream()) {
            return new String(in.readAllBytes(), StandardCharsets.UTF_8);
        } catch (IOException ex) {
            throw new UncheckedIOException("failed to read scaffold resource " + r.getDescription(), ex);
        }
    }
}
