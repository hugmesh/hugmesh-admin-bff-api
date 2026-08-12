package net.hugmesh.adminbff.optionalservices;

import org.springframework.stereotype.Component;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * The built-in, closed registry of the OPTIONAL cluster-service slugs this controller
 * reconciles — the Java mirror of the generator's
 * {@code specs/cluster/optional-services.yaml} + the {@code installed-services}
 * ConfigMap + the {@code apps/13a-optional-services.yaml} element list.
 *
 * <p>SCOPE (verified 2026-07-11 against those three sources): the 12 CLUSTER-service
 * slugs that have BOTH a 13a ApplicationSet element AND an {@code installed-services}
 * ConfigMap boolean, so each maps 1:1 to each write target. DELIBERATELY EXCLUDED and
 * documented in {@code docs/OPTIONAL-SERVICES.md §7.1}:
 * <ul>
 *   <li>{@code workloadConsole} — a ConfigMap boolean but NO 13a element (its RBAC is
 *       the hardcoded {@code apps/14-workload-console-rbac.yaml}); toggling it here
 *       would half-actuate. Left build-determined.</li>
 *   <li>{@code egress-vpn} / {@code tor} — NODE services (OpenRC + node reconcile
 *       agents), not cluster Applications: no 13a element, no ConfigMap boolean.</li>
 * </ul>
 *
 * <p>path/namespace/mountAt are INTRINSIC to a slug and resolved here (not settable on
 * the CR) so an admin cannot repoint a slug at an arbitrary manifest path. The
 * reconciler flips the 13a element / ConfigMap key BY SLUG (read-modify-write), so the
 * write path does not depend on these values; they back {@link #applicationName} +
 * status/audit. Keep this set identical to the CRD {@code spec.slug} enum, the
 * {@code apps/16} {@code ignoreDifferences} data-key list, and the 13a elements.
 */
@Component
public class OptionalServiceRegistry {

    /** One immutable registry entry (mirrors an installed-services services.json row). */
    public record Entry(String slug, String namespace, String mountAt) {}

    // Order mirrors apps/13a-optional-services.yaml + the installed-services ConfigMap.
    private static final List<Entry> ENTRIES = List.of(
            new Entry("akkoma",           "hugmesh-backend",   "/social/mastodon"),
            new Entry("tuwunel",          "hugmesh-backend",   "/social/matrix"),
            new Entry("phpbb",            "hugmesh-forum",     "/social/forum"),
            new Entry("games",            "hugmesh-games",     "/games"),
            new Entry("owncast",          "hugmesh-owncast",   "/owncast"),
            new Entry("tube",             "hugmesh-tube",      "/tube"),
            new Entry("character-studio", "hugmesh-frontend",  "/character-studio"),
            new Entry("anubis",           "hugmesh-frontend",  null),
            new Entry("coturn",           "hugmesh-backend",   null),
            new Entry("edge-ai",          "hugmesh-inference", "/admin/edge-ai"),
            new Entry("edge-ai-analysis", "hugmesh-inference", "/admin/edge-ai-analysis"),
            new Entry("edge-ai-tts",      "hugmesh-inference", "/admin/edge-ai-tts")
    );

    private final Map<String, Entry> bySlug;
    private final List<String> slugs;

    public OptionalServiceRegistry() {
        Map<String, Entry> m = new LinkedHashMap<>();
        for (Entry e : ENTRIES) {
            m.put(e.slug(), e);
        }
        this.bySlug = Map.copyOf(m);
        this.slugs = ENTRIES.stream().map(Entry::slug).toList();
    }

    /** The closed slug set, in ApplicationSet/ConfigMap order. */
    public List<String> slugs() {
        return slugs;
    }

    /** True iff this slug is a controller-managed optional cluster service. */
    public boolean isKnown(String slug) {
        return bySlug.containsKey(slug);
    }

    public Entry entry(String slug) {
        return bySlug.get(slug);
    }

    /** The Application the 13a ApplicationSet generates for this slug ({@code optional-<slug>}). */
    public String applicationName(String slug) {
        return "optional-" + slug;
    }
}
