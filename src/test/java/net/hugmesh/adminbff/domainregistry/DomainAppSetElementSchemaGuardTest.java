package net.hugmesh.adminbff.domainregistry;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.yaml.snakeyaml.Yaml;

import java.io.InputStream;
import java.lang.reflect.RecordComponent;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * CROSS-REPO SCHEMA GUARD for hugmesh-admin-bff-api issue #6 (the multi-tenancy provisioning
 * leg). It pins the ONE fact the #6 proposal turns on: what a {@code domain_registry} row would
 * have to supply for the generator's {@code casdoor-domains} ApplicationSet to accept it as an
 * element — and which of those fields this repo CANNOT supply today.
 *
 * <p><b>This is a test-only commit and it is INERT by construction.</b> Nothing in
 * {@code src/main} is added, changed, or wired by it: there is no {@code DomainReconciler}, no
 * ApplicationSet patcher, no bean, no flag, no ArgoCD object. {@link
 * #domainRegistryPackage_stillWiresNoApplicationSetWriter()} asserts exactly that, so the guard
 * fails the build the day someone starts building the reconciler — at which point they are meant
 * to re-read the proposal on #6 and update this test deliberately.
 *
 * <h3>Why the guard lives here and not in the generator</h3>
 * hugmesh-generator's {@code tests/scripts/test-casdoor-domains-appset.sh} already pins the
 * ApplicationSet's own shape (name, goTemplate, {@code elements: []}, the selector, the kustomize
 * patch targets, the PVC {@code Prune=false}, the two roots' {@code ignoreDifferences} keystone,
 * kind-profile membership). What NO test on either side covers is the JOIN: the element field
 * set the template actually dereferences versus the columns {@link DomainRegistryRow} actually
 * has. That join is the whole content of #6's blocker, and only this repo knows the row shape.
 *
 * <h3>The fixture</h3>
 * {@code /domainregistry/05b-casdoor-domains.yaml} is a VERBATIM copy of hugmesh-generator's
 * {@code specs/cluster/apps/05b-casdoor-domains.yaml} at commit {@code a6b78a11} (the file's own
 * last-touch commit; generator main was {@code 580e403b} when it was vendored),
 * sha256 {@code 37c9091eafbf8554f08fa658b4bca895bc846fea0ad161aa855140be04f1ae0a}. The vendoring
 * posture is {@link net.hugmesh.adminbff.optionalservices.OptionalServiceManifestDriftTest}'s
 * EXACTLY: the copy is authoritative for the schema assertions (they always run, CI included),
 * and {@link #vendoredAppSet_matchesGeneratorSource()} additionally compares it back to a
 * generator checkout when one is present and SKIPS when it is not. It reuses the EXISTING
 * {@code optionalservices.source.dir} property (already forwarded to the forked test JVM by the
 * pom, and already pointing at {@code ../hugmesh-generator/specs/cluster}) rather than
 * introducing a second property for the same directory — so this commit does not touch the pom.
 */
class DomainAppSetElementSchemaGuardTest {

    private static final String FIXTURE = "/domainregistry/05b-casdoor-domains.yaml";
    /** The generator path the fixture is a copy of (relative to {@code specs/cluster}). */
    private static final String SOURCE_REL = "apps/05b-casdoor-domains.yaml";

    /** A goTemplate field dereference inside the ApplicationSet template: <code>{{ .field }}</code>. */
    private static final Pattern REF = Pattern.compile("\\{\\{\\s*\\.([A-Za-z_][A-Za-z0-9_]*)\\s*}}");

    /**
     * The element keys a {@code domain_registry} row can supply TODAY, and the row accessor each
     * one comes from. Deliberately small: it is the measured answer, not an aspiration.
     */
    private static final Map<String, String> DECIDED_SOURCES = Map.of(
            "clusterDomain", "clusterDomain",
            "casdoorOrg", "casdoorOrg",
            "nsPrefix", "nsPrefix");

    /**
     * The element keys with NO decided source in this repo — the #6 blocker, one line of reason
     * each. {@code slug} is the odd one out: a CANDIDATE column exists ({@code brand}), but the
     * rule (brand vs ns_prefix vs derived from cluster_domain) is an open operator decision, and
     * the slug also names the Vault path {@code secret/<slug>/casdoor}, so guessing it wrong
     * mis-addresses a secret rather than merely mis-naming an Application.
     */
    private static final Map<String, String> UNDECIDED = Map.of(
            "slug", "candidate column `brand` exists but the slug RULE is undecided "
                    + "(brand | ns_prefix | derived from cluster_domain); it also names the Vault "
                    + "path secret/<slug>/casdoor",
            "idp", "no `idp` column exists on domain_registry at all (own|superdomain landed in "
                    + "the Studio/KEYS manifest via generator PR #71, never in this schema)",
            "selinuxLevel", "MCS category: no column and no allocator; docs/SECURITY.md §3 "
                    + "requires cluster-UNIQUE categories and 05b says the element writer owns "
                    + "the allocation",
            "selinuxLevelPg", "MCS category for the per-domain Postgres: same as selinuxLevel");

    // ── the vendored ApplicationSet ───────────────────────────────────────────────────

    @Test
    @DisplayName("the vendored 05b still ships the EMPTY scaffold with a TOTAL element schema")
    void vendoredAppSet_isTheEmptyScaffoldWithATotalSchema() {
        Map<String, Object> spec = appSetSpec();

        assertThat(spec.get("goTemplate"))
                .as("05b must stay goTemplate: true — the element field references depend on it")
                .isEqualTo(Boolean.TRUE);
        assertThat(asStrings(spec.get("goTemplateOptions")))
                .as("missingkey=error makes EVERY element field REQUIRED — it is why a partial "
                        + "projection from domain_registry cannot be shipped as 'good enough'")
                .contains("missingkey=error");

        assertThat(listGeneratorElements())
                .as("the 13a scaffold rule: git carries ZERO elements, so 05b creates NOTHING "
                        + "until a writer supplies a domain")
                .isEmpty();

        assertThat(selectorMatchLabels())
                .as("the selector gate — an element whose idp is not \"own\" generates no "
                        + "Application, and REMOVING one PRUNES it (prune: true)")
                .containsEntry("idp", "own");
    }

    @Test
    @DisplayName("the required element key set is exactly the seven fields #6 must supply")
    void requiredElementKeys_areTheSevenFieldsTheProposalNames() {
        Set<String> required = requiredElementKeys();

        // Anti-vacuity: a broken regex or a restructured file must fail LOUDLY, not silently
        // shrink the requirement set to nothing.
        assertThat(templateBlob())
                .as("the ApplicationSet template must be non-trivial — otherwise every "
                        + "assertion below passes vacuously")
                .hasSizeGreaterThan(500);
        assertThat(required)
                .as("fewer than five element references means the extraction broke, not that "
                        + "the schema shrank")
                .hasSizeGreaterThanOrEqualTo(5);

        assertThat(required)
                .as("the element schema 05b enforces. If this set changed upstream, the #6 "
                        + "proposal's projection changed with it — re-read "
                        + "https://github.com/hugmesh/hugmesh-admin-bff-api/issues/6 before "
                        + "editing this expectation")
                .containsExactlyInAnyOrder(
                        "slug", "clusterDomain", "casdoorOrg", "nsPrefix",
                        "selinuxLevel", "selinuxLevelPg", "idp");
    }

    // ── the join: element schema vs. the row this repo actually has ───────────────────

    @Test
    @DisplayName("domain_registry can supply only 3 of the 7 required element fields")
    void theProjectionGap_isExactlyTheFourUndecidedFields() {
        Set<String> required = requiredElementKeys();
        Set<String> rowComponents = rowComponentNames();

        // Every DECIDED source must still exist on the row (a rename would silently break the
        // half of the projection that IS settled).
        for (Map.Entry<String, String> e : DECIDED_SOURCES.entrySet()) {
            assertThat(rowComponents)
                    .as("element field '%s' is sourced from DomainRegistryRow.%s()",
                            e.getKey(), e.getValue())
                    .contains(e.getValue());
        }

        Set<String> unsourced = new TreeSet<>(required);
        unsourced.removeAll(DECIDED_SOURCES.keySet());

        String why = UNDECIDED.entrySet().stream()
                .map(e -> "  - " + e.getKey() + ": " + e.getValue())
                .collect(Collectors.joining("\n"));
        assertThat(unsourced)
                .as("""
                        The #6 provisioning leg is BLOCKED on these element fields, not on \
                        writing the reconciler:
                        %s
                        A reconciler that emits an element missing any of them is refused by \
                        goTemplateOptions missingkey=error; one that GUESSES them mis-addresses \
                        a Vault path or collides two workloads on one MCS category. If this set \
                        shrank, a decision was made — record it on issue #6 and update this \
                        guard in the same commit.""", why)
                .containsExactlyInAnyOrderElementsOf(new TreeSet<>(UNDECIDED.keySet()));
    }

    @Test
    @DisplayName("the row still has NO idp / MCS columns, and still has the band-190 ack targets")
    void rowShape_isStillThePreDecisionShape() {
        Set<String> components = rowComponentNames();

        assertThat(components)
                .as("adding any of these columns means the #6 decision was taken — re-read the "
                        + "proposal on issue #6 and update this guard deliberately")
                .doesNotContain("idp", "selinuxLevel", "selinuxLevelPg");

        assertThat(components)
                .as("the band-190 provisioning-status columns are the ack endpoint's write "
                        + "surface (changelog 190-domain-registry-provisioning-status.xml); "
                        + "they are READ-only today — nothing in this repo writes them")
                .contains("caProvisioned", "appsetRegistered", "lastReconciledGeneration");
    }

    @Test
    @DisplayName("this commit wires NO ApplicationSet writer — the guard is inert")
    void domainRegistryPackage_stillWiresNoApplicationSetWriter() throws Exception {
        Path pkg = Path.of("src/main/java/net/hugmesh/adminbff/domainregistry");
        // ASSERT, not assume: a guard that SKIPS when it cannot see the sources is a guard that
        // passes vacuously (the other two source scans on this branch assert the same way).
        assertThat(Files.isDirectory(pkg))
                .as("main sources must be scannable from surefire's working directory (%s)",
                        pkg.toAbsolutePath())
                .isTrue();

        List<String> offenders = new ArrayList<>();
        try (var paths = Files.list(pkg)) {
            for (Path p : paths.filter(p -> p.toString().endsWith(".java")).toList()) {
                // COMMENT-STRIPPED (string/char/text-block aware): five of these files
                // already DISCUSS the ApplicationSet in javadoc, and a scanner that counted
                // prose would be measuring documentation instead of wiring. String literals
                // are deliberately KEPT — an `APPSET_NAME = "casdoor-domains"` constant is
                // exactly the thing this must catch.
                String code = stripComments(Files.readString(p, StandardCharsets.UTF_8));
                if (code.contains("ApplicationSet") || code.contains("KubernetesClient")
                        || code.contains("genericKubernetesResources")
                        || code.contains("casdoor-domains")) {
                    offenders.add(p.getFileName().toString());
                }
            }
        }
        assertThat(offenders)
                .as("""
                        A cluster writer appeared in the domainregistry package. That is the #6 \
                        provisioning leg being built — which is fine, and expected, but it must \
                        follow the proposal on \
                        https://github.com/hugmesh/hugmesh-admin-bff-api/issues/6 (RBAC pinned to \
                        resourceNames [casdoor-domains], the ignoreDifferences keystone, the \
                        enabled=false GC rule, the fail-closed refusal of a malformed row). \
                        Update this guard in the SAME commit that builds it.""")
                .isEmpty();
    }

    // ── drift back to the generator, when a checkout is present ───────────────────────

    @Test
    @DisplayName("the vendored copy still matches a generator checkout (skips without one)")
    void vendoredAppSet_matchesGeneratorSource() throws Exception {
        Path dir = Path.of(System.getProperty("optionalservices.source.dir",
                "../hugmesh-generator/specs/cluster"));
        Path source = dir.resolve(SOURCE_REL);
        assumeTrue(Files.isRegularFile(source),
                "generator checkout not present (" + source.toAbsolutePath()
                        + ") — the vendored fixture is authoritative here and every schema "
                        + "assertion above still runs");

        assertThat(fixtureText())
                .as("the vendored %s drifted from the generator source — re-vendor it and "
                        + "re-check the #6 projection gap in the same commit", SOURCE_REL)
                .isEqualTo(Files.readString(source, StandardCharsets.UTF_8));
    }

    // ── helpers ──────────────────────────────────────────────────────────────────────

    private static String fixtureText() throws Exception {
        try (InputStream in = DomainAppSetElementSchemaGuardTest.class.getResourceAsStream(FIXTURE)) {
            assertThat(in).as("vendored fixture %s is on the test classpath", FIXTURE).isNotNull();
            return new String(in.readAllBytes(), StandardCharsets.UTF_8);
        }
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> appSet() {
        try {
            Object doc = new Yaml().load(fixtureText());
            assertThat(doc).isInstanceOf(Map.class);
            Map<String, Object> m = (Map<String, Object>) doc;
            assertThat(m.get("kind")).isEqualTo("ApplicationSet");
            assertThat(((Map<String, Object>) m.get("metadata")).get("name"))
                    .isEqualTo("casdoor-domains");
            return m;
        } catch (Exception e) {
            throw new AssertionError("cannot read/parse " + FIXTURE, e);
        }
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> appSetSpec() {
        return (Map<String, Object>) appSet().get("spec");
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> firstGenerator() {
        List<Object> gens = (List<Object>) appSetSpec().get("generators");
        assertThat(gens).as("05b must carry a generator").isNotEmpty();
        return (Map<String, Object>) gens.get(0);
    }

    @SuppressWarnings("unchecked")
    private static List<Object> listGeneratorElements() {
        Map<String, Object> list = (Map<String, Object>) firstGenerator().get("list");
        assertThat(list).as("generators[0] must be the list generator").isNotNull();
        Object elements = list.get("elements");
        assertThat(elements).as("generators[0].list.elements must be present").isInstanceOf(List.class);
        return (List<Object>) elements;
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> selectorMatchLabels() {
        Map<String, Object> sel = (Map<String, Object>) firstGenerator().get("selector");
        assertThat(sel).as("generators[0].selector must be present").isNotNull();
        return (Map<String, Object>) sel.get("matchLabels");
    }

    /** The ApplicationSet template, re-serialised — every goTemplate reference lives in here. */
    private static String templateBlob() {
        return new Yaml().dump(appSetSpec().get("template"));
    }

    /**
     * The element keys 05b actually REQUIRES: every {@code {{ .field }}} the template
     * dereferences, plus every key the generator's selector matches on (the selector reads
     * element keys, not template output — {@code idp} is required for that reason alone and
     * appears in no {@code {{ }}}).
     */
    private static Set<String> requiredElementKeys() {
        Set<String> keys = new LinkedHashSet<>();
        Matcher m = REF.matcher(templateBlob());
        while (m.find()) {
            keys.add(m.group(1));
        }
        selectorMatchLabels().keySet().forEach(k -> keys.add(String.valueOf(k)));
        return keys;
    }

    /** Record-component names of {@link DomainRegistryRow} — the row shape, by reflection. */
    private static Set<String> rowComponentNames() {
        RecordComponent[] comps = DomainRegistryRow.class.getRecordComponents();
        assertThat(comps).as("DomainRegistryRow must stay a record").isNotEmpty();
        return Arrays.stream(comps).map(RecordComponent::getName)
                .collect(Collectors.toCollection(LinkedHashSet::new));
    }

    @SuppressWarnings("unchecked")
    private static List<String> asStrings(Object o) {
        return o instanceof List<?> l
                ? l.stream().map(String::valueOf).toList()
                : List.of();
    }
    /**
     * Strip Java comments (line, block and javadoc) while respecting string, text-block and char
     * literals. Copied verbatim from {@code DeviceDialAlgorithmPolicyTest} (same repo, same
     * purpose): a structural scan of production sources that did NOT strip prose would flag every
     * file whose javadoc merely mentions the ApplicationSet, which is five of the six here.
     */
    private static String stripComments(String source) {
        StringBuilder out = new StringBuilder(source.length());
        int i = 0;
        int n = source.length();
        while (i < n) {
            char c = source.charAt(i);
            if (c == '/' && i + 1 < n && source.charAt(i + 1) == '/') {
                while (i < n && source.charAt(i) != '\n') {
                    i++;
                }
            } else if (c == '/' && i + 1 < n && source.charAt(i + 1) == '*') {
                i += 2;
                while (i + 1 < n && !(source.charAt(i) == '*' && source.charAt(i + 1) == '/')) {
                    i++;
                }
                i = Math.min(n, i + 2);
            } else if (c == '"' && source.startsWith("\"\"\"", i)) {
                out.append("\"\"\"");
                i += 3;
                while (i < n && !source.startsWith("\"\"\"", i)) {
                    i++;
                }
                i = Math.min(n, i + 3);
                out.append("\"\"\"");
            } else if (c == '"' || c == '\'') {
                char quote = c;
                out.append(c);
                i++;
                while (i < n && source.charAt(i) != quote) {
                    if (source.charAt(i) == '\\' && i + 1 < n) {
                        out.append(source.charAt(i));
                        i++;
                    }
                    out.append(source.charAt(i));
                    i++;
                }
                if (i < n) {
                    out.append(source.charAt(i));
                    i++;
                }
            } else {
                out.append(c);
                i++;
            }
        }
        return out.toString();
    }
}
