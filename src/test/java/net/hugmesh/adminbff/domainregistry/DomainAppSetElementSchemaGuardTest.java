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
 * leg). It pins the JOIN the whole issue turns on: what a {@code domain_registry} row has to
 * supply for the generator's per-domain Casdoor ApplicationSet to accept it as an element, and
 * which row column each of those fields comes from.
 *
 * <p><b>Updated for operator DECISION 29 (2026-09-17).</b> This guard used to assert a GAP —
 * four required element fields with no source in this schema, which is what made the leg
 * unbuildable. The decision closed all four ({@code slug = ns_prefix}; an {@code idp} column;
 * an MCS pair allocated by the writer at insert), so the guard now asserts the gap is CLOSED
 * and that each field keeps its decided source. It fails the day a column is dropped or an
 * element field appears upstream with no answer behind it.
 *
 * <p><b>THE ROW IS NOT THE WIRE.</b> Two joins have to hold, and this guard pins BOTH, because
 * closing the first alone changes nothing on a cluster: (1) element field &rarr; {@link
 * DomainRegistryRow} column, and (2) element field &rarr; the SIGNED EXPORT entry ({@link
 * net.hugmesh.adminbff.domainregistry.DomainExportModels.DomainEntry}), which is the only wire
 * out of this service. A column the export does not carry is invisible to the generator's
 * {@code hugmesh-domain-reconcile}: it read {@code .body.entries[i].idp} for weeks while the
 * export had no such field, saw absent, and reconciled every domain as {@code superdomain}.
 *
 * <p><b>The leg itself is still NOT built, and that is still asserted.</b> Nothing in
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
     * EVERY element key, and the {@link DomainRegistryRow} accessor it is sourced from —
     * CLOSED by operator DECISION 29 (2026-09-17). Before that decision this map held three
     * entries and a companion {@code UNDECIDED} map held the other four; the four are:
     *
     * <ul>
     *   <li>{@code slug} &rarr; {@code nsPrefix} (29a: <em>"the slug rule is ns_prefix — it also
     *       names the Vault path secret/&lt;slug&gt;/casdoor, so namespace and secret path now
     *       agree"</em>). This is why {@code slug} and {@code nsPrefix} map to the SAME
     *       accessor, and why that column is UNIQUE + DNS-1123 validated + immutable.</li>
     *   <li>{@code idp} &rarr; {@code idp} (29b: add the column rather than derive it).</li>
     *   <li>{@code selinuxLevel} / {@code selinuxLevelPg} &rarr; the allocated MCS pair
     *       (29c: the writer allocates at insert under a uniqueness constraint).</li>
     * </ul>
     *
     * <p>If an entry here loses its row accessor, the provisioning leg went back to being
     * unbuildable — that is a regression, not a refactor.
     */
    private static final Map<String, String> DECIDED_SOURCES = Map.of(
            "slug", "nsPrefix",
            "clusterDomain", "clusterDomain",
            "casdoorOrg", "casdoorOrg",
            "nsPrefix", "nsPrefix",
            "idp", "idp",
            "selinuxLevel", "selinuxLevel",
            "selinuxLevelPg", "selinuxLevelPg");

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
    @DisplayName("the projection gap is CLOSED AT THE ROW: every element field has a column")
    void theProjectionGap_isClosedByDecision29() {
        Set<String> required = requiredElementKeys();
        Set<String> rowComponents = rowComponentNames();

        // Every DECIDED source must exist on the row. A rename here silently un-builds the leg.
        for (Map.Entry<String, String> e : DECIDED_SOURCES.entrySet()) {
            assertThat(rowComponents)
                    .as("element field '%s' is sourced from DomainRegistryRow.%s() — decision 29",
                            e.getKey(), e.getValue())
                    .contains(e.getValue());
        }

        Set<String> unsourced = new TreeSet<>(required);
        unsourced.removeAll(DECIDED_SOURCES.keySet());

        String mapping = DECIDED_SOURCES.entrySet().stream()
                .sorted(Map.Entry.comparingByKey())
                .map(e -> "  - " + e.getKey() + " <- DomainRegistryRow." + e.getValue() + "()")
                .collect(Collectors.joining("\n"));
        assertThat(unsourced)
                .as("""
                        An element field 05b requires has NO source on domain_registry, so the \
                        #6 provisioning leg is blocked again. This is the ROW half only — see \
                        exportEntry_carriesEveryDecidedField for the WIRE half; a column the \
                        signed export does not carry reaches no cluster. The decision-29 \
                        mapping is:
                        %s
                        An element missing any required field is refused by goTemplateOptions \
                        missingkey=error; one that GUESSES a field mis-addresses the Vault path \
                        secret/<slug>/casdoor or collides two workloads on one MCS category. \
                        If a NEW field appeared upstream, it needs an operator decision and a \
                        column — record it on issue #6 and update this guard in the same \
                        commit.""", mapping)
                .isEmpty();
    }

    @Test
    @DisplayName("the row carries the decision-29 columns, and still has the band-190 ack targets")
    void rowShape_carriesTheDecision29Columns() {
        Set<String> components = rowComponentNames();

        assertThat(components)
                .as("""
                        DECISION 29 (operator, 2026-09-17) put these on domain_registry via \
                        changelog 012: idp (29b, a real column not a derivation) and the \
                        allocated MCS pair (29c, allocated by the writer at insert under \
                        uq_domain_registry_selinux_level/_pg). Removing one reverts the \
                        decision and re-blocks the provisioning leg.""")
                .contains("idp", "selinuxLevel", "selinuxLevelPg");

        assertThat(components)
                .as("the band-190 provisioning-status columns are the ack endpoint's write "
                        + "surface (changelog 190-domain-registry-provisioning-status.xml); "
                        + "they are READ-only today — nothing in this repo writes them")
                .contains("caProvisioned", "appsetRegistered", "lastReconciledGeneration");
    }

    @Test
    @DisplayName("the slug rule stays ns_prefix (29a) — slug and nsPrefix share one source")
    void slugRule_isNsPrefix() {
        assertThat(DECIDED_SOURCES.get("slug"))
                .as("""
                        Decision 29a: the slug rule is ns_prefix, NOT brand and NOT derived \
                        from cluster_domain. The slug names the Application casdoor-<slug>, the \
                        namespace <slug>-pki AND the Vault path secret/<slug>/casdoor, so \
                        sourcing it from a different column re-points a live secret. If this \
                        assertion is edited, the Vault path convention moved with it and \
                        docs/DOMAIN-IDP.md has to move too.""")
                .isEqualTo("nsPrefix");
        assertThat(DECIDED_SOURCES.get("slug"))
                .as("slug and nsPrefix are ONE column under 29a — they cannot diverge")
                .isEqualTo(DECIDED_SOURCES.get("nsPrefix"));

        assertThat(rowComponentNames())
                .as("29a again, from the production side: the row has NO separate 'slug' "
                        + "component, so ns_prefix is the ONLY column the slug can come from — "
                        + "a second column would let the Application name and the Vault path "
                        + "drift apart")
                .doesNotContain("slug")
                .contains("nsPrefix");

        assertThat(DomainSlug.pkiNamespace("acme"))
                .as("the tenant namespace the ApplicationSet destination expands to")
                .isEqualTo("acme-pki");
        assertThat(DomainSlug.vaultPath("acme"))
                .as("the per-domain Vault credential document the three ExternalSecrets read")
                .isEqualTo("secret/acme/casdoor");
    }

    /**
     * The WIRE half of the join. Every element field 05b requires must be carried by the signed
     * export entry, under its own name or its decided row-source name — otherwise the column
     * exists, the guard above is green, and the generator still sees nothing.
     *
     * <p>This is not hypothetical: hugmesh-generator
     * {@code specs/usr/sbin/hugmesh-domain-reconcile:413} reads
     * {@code .body.entries[i].idp} and validates it as a closed enum at :429-431, and that
     * file's own header recorded the producer gap ("the DomainEntry has NO idp field yet …
     * every current export renders the pre-#47 template set unchanged"). Decision 29b made the
     * column real so it could be CARRIED.
     */
    @Test
    @DisplayName("the wire carries them too: the export entry has every decided field")
    void exportEntry_carriesEveryDecidedField() {
        Set<String> wire = Arrays.stream(
                        net.hugmesh.adminbff.domainregistry.DomainExportModels.DomainEntry.class
                                .getRecordComponents())
                .map(RecordComponent::getName)
                .collect(Collectors.toCollection(LinkedHashSet::new));

        assertThat(wire)
                .as("anti-vacuity: DomainEntry must still be a record with a real field set")
                .hasSizeGreaterThanOrEqualTo(10);

        List<String> missing = new ArrayList<>();
        for (Map.Entry<String, String> e : DECIDED_SOURCES.entrySet()) {
            if (!wire.contains(e.getKey()) && !wire.contains(e.getValue())) {
                missing.add(e.getKey() + " (row source: " + e.getValue() + ")");
            }
        }
        assertThat(missing)
                .as("""
                        These element fields have a domain_registry column but the SIGNED EXPORT \
                        does not carry them, so no consumer can ever see them: the row is not \
                        the wire. DomainEntry today: %s. Add the field to DomainEntry AND to \
                        DomainRegistryExportService.compile — but NOT to canonicalBytes without \
                        moving hugmesh-generator specs/usr/lib/hugmesh/domain-verify.sh in \
                        lockstep, because that verifier rebuilds the v1 bytes field by field and \
                        fails CLOSED on divergence.""", wire)
                .isEmpty();

        assertThat(wire)
                .as("DECISION 29b/29c on the wire — dropping one of these silently reverts "
                        + "every exported domain to the superdomain IdP and to no MCS pair")
                .contains("idp", "selinuxLevel", "selinuxLevelPg");
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
