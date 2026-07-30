package systems.hugmesh.adminbff.servicecatalog.scaffold;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * The EMBEDDED scaffold catalog — the fixed, ordered set of example starter codebases the
 * Service-Store wizard can render, each backed by a vendored classpath tree under
 * {@code resources/scaffold/<name>/} (provenance in {@code resources/scaffold/README.md}).
 *
 * <p>Pure + static: the catalog is a compile-time constant (no I/O, no Spring), so it is
 * cheap to consult from both the archetypes read endpoint and the create-request validation
 * (an {@code archetype} that is not {@link #contains a member} is a clean 400). {@link #of}
 * is the by-name lookup the renderer uses to resolve the classpath root.
 *
 * <p>{@code spring-bff} feeds a Java package ({@code systems.hugmesh.<slug>}), so its
 * rendered {@code APP_SLUG} MUST be package-safe ({@code ^[a-z0-9]+$}); {@link #requiresJavaPackageSafeSlug}
 * flags it so {@link ScaffoldService} rejects a hyphenated/empty slug BEFORE persisting.
 */
public final class ScaffoldCatalog {

    /** The {@code spring-bff} archetype id — feeds a Java package, so its slug must be
     *  {@code ^[a-z0-9]+$} (no hyphens). */
    public static final String SPRING_BFF = "spring-bff";

    private static final List<ScaffoldArchetype> ARCHETYPES = List.of(
            new ScaffoldArchetype(SPRING_BFF, "Spring Boot BFF",
                    "Minimal, runnable Spring Boot 4 WebFlux BFF (Java 25, hugmesh-parent) "
                            + "with a health chain + one hello endpoint.",
                    "backend"),
            new ScaffoldArchetype("angular-mfe", "Angular remote (MFE)",
                    "Angular 22 native-federation remote exposing ./routes — a micro-frontend "
                            + "the host shell mounts.",
                    "remote-shell"),
            new ScaffoldArchetype("angular-host", "Angular host shell",
                    "Angular 22 native-federation host shell that unions a dynamic "
                            + "/api/federation/manifest over a static remote floor.",
                    "host"),
            new ScaffoldArchetype("remote-fragment", "Remote fragment",
                    "A profile/remote-fragment starter pointing at the real base codebase as "
                            + "the worked example.",
                    "fragment"));

    /** Archetype ids whose rendered {@code APP_SLUG} must be Java-package-safe ({@code ^[a-z0-9]+$}). */
    private static final java.util.Set<String> JAVA_PACKAGE_ARCHETYPES = java.util.Set.of(SPRING_BFF);

    private static final Map<String, ScaffoldArchetype> BY_NAME = index();

    private ScaffoldCatalog() {
    }

    private static Map<String, ScaffoldArchetype> index() {
        Map<String, ScaffoldArchetype> m = new LinkedHashMap<>();
        for (ScaffoldArchetype a : ARCHETYPES) {
            m.put(a.name(), a);
        }
        return m;
    }

    /** The catalog in stable declaration order (the archetypes read endpoint payload). */
    public static List<ScaffoldArchetype> all() {
        return ARCHETYPES;
    }

    /** The archetype for {@code name}, or {@code null} if it is not a catalog member. */
    public static ScaffoldArchetype of(String name) {
        return name == null ? null : BY_NAME.get(name);
    }

    /** Whether {@code name} is a catalog member (the create-request {@code archetype} gate). */
    public static boolean contains(String name) {
        return of(name) != null;
    }

    /** Whether the archetype's rendered {@code APP_SLUG} must be Java-package-safe
     *  ({@code ^[a-z0-9]+$}, no hyphens) because it becomes a Java package segment. */
    public static boolean requiresJavaPackageSafeSlug(String name) {
        return JAVA_PACKAGE_ARCHETYPES.contains(name);
    }
}
