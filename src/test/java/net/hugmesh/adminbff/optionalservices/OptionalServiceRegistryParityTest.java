package net.hugmesh.adminbff.optionalservices;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.yaml.snakeyaml.Yaml;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * THE ANTI-{@code character-forge} TEST — the standing proof that the Java
 * {@link OptionalServiceRegistry}, the CRD {@code spec.slug} enum, the seed CRs, the
 * {@code apps/13a} ApplicationSet elements, the {@code installed-services} ConfigMap booleans
 * and {@code apps/16}'s {@code ignoreDifferences} pointers all still agree.
 *
 * <h3>The bug class this closes</h3>
 * {@code character-forge} was in the CRD enum, had a seed CR, had a 13a element and had a
 * ConfigMap boolean — and was MISSING from {@link OptionalServiceRegistry}. The API server
 * therefore ACCEPTED {@code spec.slug: character-forge}, {@code kubectl} reported
 * {@code enabled: true}, and {@link OptionalServiceReconciler} logged "unknown slug — ignoring",
 * wrote NEITHER target, and skipped that CR's {@code /status} entirely. A toggle that reports
 * success and does nothing, with no trace anywhere. Fixing the one entry was cheap; making the
 * SHAPE impossible is this test.
 *
 * <h3>How it avoids being a vacuous pass</h3>
 * Every side is DERIVED by parsing the manifest, never restated as a Java literal:
 * <ul>
 *   <li>each derivation goes through {@link #derived(String, Set)}, which THROWS on an empty
 *       result — an assertion over an empty derived list would otherwise pass for free, which
 *       is precisely how a "closed 1:1 set" turned out to hold FIVE different cardinalities;</li>
 *   <li>the not-toggleable REASONS are re-derived from the manifests and compared to the
 *       registry's, so the second half of the registry cannot rot into decoration either (the
 *       "registry row nothing reads" shape);</li>
 *   <li>the CLOSURE assertion (registry known-set == union of every upstream source) means a
 *       slug added upstream fails this build until somebody classifies it, in EITHER half;</li>
 *   <li>the last test drives the real {@link OptionalServiceReconciler} over the registry and
 *       asserts every managed slug is actuated AND status-written — a registry entry that the
 *       reconciler still ignores would pass every set comparison above and fail here.</li>
 * </ul>
 *
 * <h3>Provenance of the fixtures</h3>
 * {@code src/test/resources/optionalservices/*.yaml} are VERBATIM copies of
 * {@code hugmesh-generator} {@code specs/cluster/...} at commit {@code 056a0e78} (main,
 * 2026-08-26), vendored because they are the cross-repo source of truth and CI builds this BFF
 * alone. {@link OptionalServiceManifestDriftTest} compares them back to a generator checkout
 * when one is present; that check SKIPS when it is not, so a stale vendored copy is a real
 * residual risk — see that class.
 */
class OptionalServiceRegistryParityTest {

    private static final String DIR = "/optionalservices/";
    private static final String CRD = DIR + "crd-optionalservice.yaml";
    private static final String SEED = DIR + "seed-optionalservices.yaml";
    private static final String APPSET = DIR + "13a-optional-services.yaml";
    private static final String CONFIGMAP = DIR + "installed-services-configmap.yaml";
    private static final String APPS16 = DIR + "16-reserved-prefixes-policy.yaml";

    private static final OptionalServiceRegistry REGISTRY = new OptionalServiceRegistry();

    // ── the five derivations (each FAILS LOUD when it yields nothing) ────────────────

    /** CRD {@code spec.slug} enum values. */
    private static Set<String> crdEnumSlugs() {
        Map<String, Object> crd = firstDoc(CRD);
        Object versions = nav(crd, "spec", "versions");
        List<?> vlist = requireList("CRD spec.versions", versions);
        Map<String, Object> v1alpha1 = null;
        for (Object o : vlist) {
            Map<String, Object> v = asMap(o);
            if (v != null && "v1alpha1".equals(v.get("name"))) {
                v1alpha1 = v;
            }
        }
        if (v1alpha1 == null) {
            throw new IllegalStateException("CRD has no v1alpha1 version — fixture " + CRD + " is wrong");
        }
        Object en = nav(v1alpha1, "schema", "openAPIV3Schema", "properties", "spec",
                "properties", "slug", "enum");
        Set<String> out = new LinkedHashSet<>();
        for (Object o : requireList("CRD spec.slug enum", en)) {
            out.add(String.valueOf(o));
        }
        return derived("CRD spec.slug enum", out);
    }

    /** {@code spec.slug} of every seed OptionalService CR. */
    private static Set<String> seedSlugs() {
        Set<String> out = new LinkedHashSet<>();
        for (Map<String, Object> doc : allDocs(SEED)) {
            if (!"OptionalService".equals(doc.get("kind"))) {
                continue;
            }
            Object slug = nav(doc, "spec", "slug");
            if (slug != null) {
                out.add(String.valueOf(slug));
            }
        }
        return derived("seed OptionalService CRs", out);
    }

    /** {@code slug} of every {@code apps/13a} inline list-generator element. */
    private static Set<String> appSetSlugs() {
        return derived("apps/13a list-generator elements", new LinkedHashSet<>(appSetSlugsInOrder()));
    }

    /** The 13a element slugs IN FILE ORDER (the registry claims to mirror this order). */
    private static List<String> appSetSlugsInOrder() {
        Map<String, Object> appSet = firstDoc(APPSET);
        Object generators = nav(appSet, "spec", "generators");
        List<?> glist = requireList("apps/13a spec.generators", generators);
        Map<String, Object> list = asMap(nav(asMap(glist.get(0)), "list"));
        if (list == null) {
            throw new IllegalStateException("apps/13a generators[0] has no list generator");
        }
        List<String> out = new ArrayList<>();
        for (Object o : requireList("apps/13a elements", list.get("elements"))) {
            Map<String, Object> el = asMap(o);
            if (el != null && el.get("slug") != null) {
                out.add(String.valueOf(el.get("slug")));
            }
        }
        if (out.isEmpty()) {
            throw new IllegalStateException("apps/13a yielded ZERO element slugs");
        }
        return out;
    }

    /**
     * {@code installed-services} data keys whose value is a BOOLEAN string — derived by value,
     * not by an exclusion list, so the embedded {@code services.json} blob (and any future
     * non-boolean key) drops out on its own.
     */
    private static Set<String> configMapBooleanSlugs() {
        Map<String, Object> data = requireMap("installed-services data", nav(firstDoc(CONFIGMAP), "data"));
        Set<String> out = new LinkedHashSet<>();
        for (Map.Entry<String, Object> e : data.entrySet()) {
            String v = String.valueOf(e.getValue()).trim();
            if ("true".equals(v) || "false".equals(v)) {
                out.add(e.getKey());
            }
        }
        return derived("installed-services boolean keys", out);
    }

    /** Slugs whose {@code /data/<slug>} pointer {@code apps/16} shields from ArgoCD selfHeal. */
    private static Set<String> apps16ProtectedSlugs() {
        Object ignore = nav(firstDoc(APPS16), "spec", "ignoreDifferences");
        Set<String> out = new LinkedHashSet<>();
        for (Object o : requireList("apps/16 spec.ignoreDifferences", ignore)) {
            Map<String, Object> diff = asMap(o);
            if (diff == null || !"ConfigMap".equals(diff.get("kind"))
                    || !"installed-services".equals(diff.get("name"))) {
                continue;
            }
            for (Object p : requireList("apps/16 jsonPointers", diff.get("jsonPointers"))) {
                String pointer = String.valueOf(p);
                if (pointer.startsWith("/data/")) {
                    out.add(pointer.substring("/data/".length()));
                }
            }
        }
        return derived("apps/16 installed-services ignoreDifferences pointers", out);
    }

    /** The {@code services.json} rows embedded in the ConfigMap, keyed by slug. */
    private static Map<String, JsonNode> servicesJsonRows() {
        Map<String, Object> data = requireMap("installed-services data", nav(firstDoc(CONFIGMAP), "data"));
        Object raw = data.get("services.json");
        if (raw == null) {
            throw new IllegalStateException("installed-services has no services.json key");
        }
        Map<String, JsonNode> out = new LinkedHashMap<>();
        try {
            JsonNode rows = new ObjectMapper().readTree(String.valueOf(raw));
            for (JsonNode row : rows) {
                out.put(row.path("slug").asText(), row);
            }
        } catch (Exception e) {
            throw new IllegalStateException("services.json in " + CONFIGMAP + " does not parse", e);
        }
        if (out.isEmpty()) {
            throw new IllegalStateException("services.json yielded ZERO rows");
        }
        return out;
    }

    // ── the parity assertions ───────────────────────────────────────────────────────

    /**
     * The managed half is EXACTLY the CRD enum and EXACTLY the seed set. This is the assertion
     * that was false for {@code character-forge}: the CRD/seed had 13, the registry had 12.
     */
    @Test
    void managedRegistry_equalsCrdEnum_andSeedCrs() {
        Set<String> registrySlugs = derived("OptionalServiceRegistry.slugs()",
                new LinkedHashSet<>(REGISTRY.slugs()));

        assertThat(sorted(registrySlugs))
                .as("OptionalServiceRegistry.slugs() vs the CRD spec.slug enum — a slug the CRD "
                        + "accepts but the registry lacks is a SILENTLY INERT toggle (the "
                        + "character-forge defect); a slug the registry has but the CRD rejects "
                        + "can never receive a CR")
                .isEqualTo(sorted(crdEnumSlugs()));

        assertThat(sorted(registrySlugs))
                .as("OptionalServiceRegistry.slugs() vs the seed OptionalService CRs — a managed "
                        + "slug with no seed CR has no desired-state object on a fresh cluster")
                .isEqualTo(sorted(seedSlugs()));
    }

    /** The specific regression, pinned by name so the fix cannot be quietly reverted. */
    @Test
    void characterForge_isManaged_notSilentlyInert() {
        assertThat(crdEnumSlugs()).as("fixture sanity: the CRD enum still offers character-forge")
                .contains("character-forge");
        assertThat(appSetSlugs()).as("fixture sanity: 13a still has a character-forge element")
                .contains("character-forge");
        assertThat(REGISTRY.isKnown("character-forge"))
                .as("character-forge MUST be reconcilable: the CRD accepts the write and the "
                        + "reconciler would otherwise log 'unknown slug — ignoring', write "
                        + "NEITHER target and skip the CR status, leaving no observable trace")
                .isTrue();
        assertThat(REGISTRY.notToggleableReason("character-forge"))
                .as("character-forge must not be parked in the not-toggleable half either")
                .isNull();
    }

    /**
     * CLOSURE: the registry's known set (managed + not-toggleable) is EXACTLY the union of every
     * upstream source. Nothing upstream is unclassified; nothing here is invented.
     */
    @Test
    void registryKnownSet_isExactlyTheUnionOfEveryUpstreamSource() {
        Set<String> upstream = new LinkedHashSet<>();
        upstream.addAll(crdEnumSlugs());
        upstream.addAll(seedSlugs());
        upstream.addAll(appSetSlugs());
        upstream.addAll(configMapBooleanSlugs());
        derived("union of all upstream optional-service sources", upstream);

        Set<String> known = derived("OptionalServiceRegistry.knownSlugs()",
                new LinkedHashSet<>(REGISTRY.knownSlugs()));

        assertThat(sorted(known))
                .as("every slug ANY optional-services source knows must be classified in the "
                        + "registry — as managed (reconcilable) or as not-toggleable WITH a named "
                        + "reason. An unclassified slug is invisible to the superadmin catalogue, "
                        + "which is how character-forge stayed inert for a whole release")
                .isEqualTo(sorted(upstream));
    }

    /** The managed half must genuinely be actionable: CRD enum value AND a 13a element. */
    @Test
    void everyManagedSlug_hasBothActuationPrerequisites() {
        Set<String> crd = crdEnumSlugs();
        Set<String> appSet = appSetSlugs();
        for (String slug : derived("OptionalServiceRegistry.slugs()", new LinkedHashSet<>(REGISTRY.slugs()))) {
            assertThat(crd).as("managed slug '%s' must be in the CRD enum or no CR can exist", slug)
                    .contains(slug);
            assertThat(appSet).as("managed slug '%s' must have a 13a element or the toggle "
                    + "half-actuates (greying only, no Application)", slug).contains(slug);
        }
    }

    /**
     * The not-toggleable half's REASONS are re-derived from the manifests, so that half cannot
     * become a decorative map that nothing checks (the "registry row nothing reads" shape).
     */
    @Test
    void everyNotToggleableSlug_carriesTheDerivedReason() {
        Set<String> crd = crdEnumSlugs();
        Set<String> appSet = appSetSlugs();
        Map<String, OptionalServiceRegistry.NotToggleable> declared = REGISTRY.notToggleable();
        assertThat(declared)
                .as("the not-toggleable half must not be empty — the platform demonstrably has "
                        + "slugs the reconciler cannot action, and an empty map here would make "
                        + "every derived-reason assertion below vacuous")
                .isNotEmpty();

        for (Map.Entry<String, OptionalServiceRegistry.NotToggleable> e : declared.entrySet()) {
            String slug = e.getKey();
            OptionalServiceRegistry.NotToggleable expected = !appSet.contains(slug)
                    ? OptionalServiceRegistry.NotToggleable.NO_APPLICATIONSET_ELEMENT
                    : OptionalServiceRegistry.NotToggleable.NOT_IN_CRD_ENUM;

            assertThat(e.getValue())
                    .as("'%s' is declared not-toggleable; the manifests say the reason is %s "
                            + "(13a element present=%s, in CRD enum=%s)",
                            slug, expected, appSet.contains(slug), crd.contains(slug))
                    .isEqualTo(expected);

            assertThat(appSet.contains(slug) && crd.contains(slug))
                    .as("'%s' is declared not-toggleable but the manifests say it has BOTH a 13a "
                            + "element and a CRD enum value — it should be MANAGED instead, which "
                            + "is exactly the character-forge mistake in the other direction", slug)
                    .isFalse();

            assertThat(REGISTRY.isKnown(slug))
                    .as("'%s' must not be in both halves", slug).isFalse();
        }
    }

    /** {@code configMapSelfHealProtected} is a fact about apps/16, so derive it from apps/16. */
    @Test
    void configMapSelfHealProtection_matchesApps16Pointers() {
        Set<String> protectedSlugs = apps16ProtectedSlugs();
        for (String slug : REGISTRY.slugs()) {
            OptionalServiceRegistry.Entry entry = REGISTRY.entry(slug);
            assertThat(entry).as("registry entry for managed slug '%s'", slug).isNotNull();
            assertThat(entry.configMapSelfHealProtected())
                    .as("apps/16 %s a /data/%s ignoreDifferences pointer, so the registry must "
                            + "report configMapSelfHealProtected=%s. Getting this wrong either "
                            + "hides a selfHeal revert from the superadmin or invents one",
                            protectedSlugs.contains(slug) ? "HAS" : "does NOT have",
                            slug, protectedSlugs.contains(slug))
                    .isEqualTo(protectedSlugs.contains(slug));
        }
    }

    /**
     * Known partial actuation, pinned deliberately: {@code apps/16} is missing four pointers,
     * one of which ({@code character-forge}) is now a MANAGED slug. That is a generator-side
     * defect this repo cannot fix, so it is recorded here as an explicit expectation instead of
     * being silently tolerated — if the generator adds the pointer and the fixture is refreshed,
     * this test goes red and the registry flag gets flipped with it.
     */
    @Test
    void managedSlugsMissingApps16Protection_areExactlyTheKnownSet() {
        Set<String> protectedSlugs = apps16ProtectedSlugs();
        Set<String> unprotectedManaged = new TreeSet<>();
        for (String slug : REGISTRY.slugs()) {
            if (!protectedSlugs.contains(slug)) {
                unprotectedManaged.add(slug);
            }
        }
        assertThat(unprotectedManaged)
                .as("MANAGED slugs whose installed-services greying key apps/16 does NOT shield "
                        + "from ArgoCD selfHeal — their toggle half-actuates. Today that is exactly "
                        + "character-forge (generator: apps/16 also omits headwind, "
                        + "attestation-server and meshbridge, but those are not-toggleable here "
                        + "for other reasons). Refresh the fixture and flip "
                        + "Entry.configMapSelfHealProtected when the generator adds the pointer")
                .containsExactly("character-forge");
    }

    /** namespace / mountAt / displayName are copied from services.json, so check them against it. */
    @Test
    void managedEntryCoordinates_matchServicesJson() {
        Map<String, JsonNode> rows = servicesJsonRows();
        for (String slug : REGISTRY.slugs()) {
            JsonNode row = rows.get(slug);
            assertThat(row).as("services.json row for managed slug '%s'", slug).isNotNull();
            OptionalServiceRegistry.Entry entry = REGISTRY.entry(slug);

            assertThat(entry.namespace())
                    .as("namespace for '%s' must match services.json", slug)
                    .isEqualTo(row.path("namespace").asText(null));
            assertThat(entry.mountAt())
                    .as("mountAt for '%s' must match services.json", slug)
                    .isEqualTo(row.path("mountAt").isNull() ? null : row.path("mountAt").asText(null));
            assertThat(entry.displayName())
                    .as("displayName for '%s' must match services.json", slug)
                    .isEqualTo(row.path("displayName").asText(null));
        }
    }

    /** The registry claims to mirror 13a's order; check the claim rather than trusting it. */
    @Test
    void managedRegistryOrder_mirrorsApps13aElementOrder() {
        List<String> expected = new ArrayList<>();
        for (String slug : appSetSlugsInOrder()) {
            if (REGISTRY.isKnown(slug)) {
                expected.add(slug);
            }
        }
        assertThat(expected).as("derived 13a-order managed slugs").isNotEmpty();
        assertThat(REGISTRY.slugs())
                .as("registry order must mirror the 13a element order (restricted to managed "
                        + "slugs) — the javadoc says so, so it has to be true")
                .containsExactlyElementsOf(expected);
    }

    /**
     * END-TO-END over the REAL reconciler: every managed slug must actually be actuated and
     * status-written. A registry entry the reconciler still drops would satisfy every set
     * comparison above and fail HERE — this is the assertion that character-forge failed.
     */
    @Test
    void reconciler_actuatesAndStatusWrites_everyManagedSlug() {
        List<OptionalServiceCr> crs = new ArrayList<>();
        for (String slug : REGISTRY.slugs()) {
            crs.add(new OptionalServiceCr(slug, "devops", slug, true, "parity", "test", 1L, "1"));
        }
        assertThat(crs).as("one CR per managed slug (empty would make this test vacuous)").isNotEmpty();

        RecordingSeams seams = new RecordingSeams(crs);
        new OptionalServiceReconciler(seams, seams, seams, REGISTRY, seams).runOnce().block();

        assertThat(seams.appliedDesired)
                .as("the ApplicationSet patcher must receive EVERY managed slug")
                .containsOnlyKeys(REGISTRY.slugs().toArray(new String[0]));
        assertThat(seams.mirroredDesired)
                .as("the ConfigMap mirror must receive EVERY managed slug")
                .containsOnlyKeys(REGISTRY.slugs().toArray(new String[0]));
        for (String slug : REGISTRY.slugs()) {
            assertThat(seams.appliedDesired.get(slug))
                    .as("desired[%s] must be TRUE — the CR asked for it", slug).isTrue();
            assertThat(seams.statusWrittenFor)
                    .as("a status MUST be written for '%s'; a slug the reconciler ignores gets no "
                            + "status at all, which is what made character-forge undetectable", slug)
                    .contains(slug);
        }
    }

    /** One object standing in for all four reconciler seams (client, patcher, writer, leader). */
    private static final class RecordingSeams implements OptionalServiceClient,
            OptionalServiceApplicationSetPatcher, InstalledServicesConfigMapWriter,
            net.hugmesh.adminbff.lease.LeaderElection {

        private final List<OptionalServiceCr> crs;
        private Map<String, Boolean> appliedDesired = Map.of();
        private Map<String, Boolean> mirroredDesired = Map.of();
        private final Set<String> statusWrittenFor = new LinkedHashSet<>();

        RecordingSeams(List<OptionalServiceCr> crs) {
            this.crs = crs;
        }

        @Override public List<OptionalServiceCr> listDesired() { return crs; }

        @Override public boolean updateStatus(OptionalServiceCr cr, OptionalServiceStatus status) {
            statusWrittenFor.add(cr.slug());
            return true;
        }

        @Override public OptionalServiceCr setEnabled(String slug, boolean enabled, String reason,
                                                      String requestedBy) {
            throw new UnsupportedOperationException("not exercised by the reconciler");
        }

        @Override public boolean apply(Map<String, Boolean> desired) {
            appliedDesired = Map.copyOf(desired);
            return true;
        }

        @Override public boolean mirror(Map<String, Boolean> desired) {
            mirroredDesired = Map.copyOf(desired);
            return true;
        }

        @Override public boolean isReal() { return true; }

        @Override public boolean isLeader() { return true; }

        @Override public String label() { return "parity-test"; }
    }

    // ── fixture plumbing (every helper fails LOUD rather than yielding empty) ────────

    /** The guard that makes an empty derivation a FAILURE instead of a free pass. */
    private static Set<String> derived(String what, Set<String> values) {
        if (values == null || values.isEmpty()) {
            throw new IllegalStateException("DERIVATION YIELDED NOTHING for " + what
                    + " — an assertion over an empty derived set passes for free, so this is a "
                    + "hard failure. Either the fixture moved or the navigation path is wrong.");
        }
        return values;
    }

    private static Set<String> sorted(Set<String> in) {
        return new TreeSet<>(in);
    }

    private static String raw(String resource) {
        try (InputStream in = OptionalServiceRegistryParityTest.class.getResourceAsStream(resource)) {
            if (in == null) {
                throw new IllegalStateException("vendored fixture " + resource + " is MISSING from "
                        + "the test classpath — the parity check cannot run, so it fails rather "
                        + "than skips");
            }
            return new String(in.readAllBytes(), StandardCharsets.UTF_8);
        } catch (IllegalStateException e) {
            throw e;
        } catch (Exception e) {
            throw new IllegalStateException("failed reading " + resource, e);
        }
    }

    private static List<Map<String, Object>> allDocs(String resource) {
        List<Map<String, Object>> docs = new ArrayList<>();
        for (Object doc : new Yaml().loadAll(raw(resource))) {
            Map<String, Object> m = asMap(doc);
            if (m != null) {
                docs.add(m);
            }
        }
        if (docs.isEmpty()) {
            throw new IllegalStateException(resource + " parsed to ZERO YAML documents");
        }
        return docs;
    }

    private static Map<String, Object> firstDoc(String resource) {
        return allDocs(resource).get(0);
    }

    /** Walk a nested map by key, returning null at the first miss. */
    private static Object nav(Map<String, Object> root, String... path) {
        Object cur = root;
        for (String key : path) {
            Map<String, Object> m = asMap(cur);
            if (m == null) {
                return null;
            }
            cur = m.get(key);
        }
        return cur;
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> asMap(Object o) {
        return (o instanceof Map<?, ?> m) ? (Map<String, Object>) m : null;
    }

    private static List<?> requireList(String what, Object o) {
        if (!(o instanceof List<?> l) || l.isEmpty()) {
            throw new IllegalStateException(what + " is missing or empty in the vendored fixture");
        }
        return l;
    }

    private static Map<String, Object> requireMap(String what, Object o) {
        Map<String, Object> m = asMap(o);
        if (m == null || m.isEmpty()) {
            throw new IllegalStateException(what + " is missing or empty in the vendored fixture");
        }
        return m;
    }
}
