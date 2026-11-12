package net.hugmesh.adminbff.device;

import com.fasterxml.jackson.core.json.JsonReadFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.json.JsonMapper;
import org.junit.jupiter.api.Test;
import net.hugmesh.adminbff.device.ExportModels.AuthorizedOperator;
import net.hugmesh.adminbff.device.ExportModels.ExportBody;

import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The pure compile leg: a signed device-license export {@link ExportBody} -> a headscale ACL
 * policy. Proves — WITHOUT a live headscale — that the compiled policy describes the SAME mesh
 * the node-side renderer (hugmesh-generator {@code specs/usr/sbin/gen-headscale-policy.sh} +
 * {@code specs/etc/headscale/policy.hujson.tmpl}) writes on every control node today. Decision
 * 101 = B (2026-09-23) retired that renderer as a writer and made this compiler (via the dark
 * {@code PUT /api/v1/policy} push) the SOLE writer, so until the generator cut-over removes the
 * renderer, reproducing its output is what makes the swap safe.
 *
 * <h3>The RECONCILIATION assertions (2026-07-30)</h3>
 * Each pins a divergence that would have broken the live mesh on the first push:
 * <ul>
 *   <li>{@link #nodeTag_isTheServerForcedDevTag_notTagNode()} — dst is
 *       {@code tag:dev_<sha256(fp)[0:12]>} (what {@code hugmesh-headscale-forcetags} assigns),
 *       with the hashes pinned to literals computed OUTSIDE Java
 *       ({@code printf '%s' FP | openssl dgst -sha256 | cut -c1-12}) so the test cannot agree
 *       with a wrong implementation by construction;</li>
 *   <li>{@link #nodeTagPrefix_isLoadBearing_everyEmittedNodeTagIsBuiltFromIt()} — the
 *       {@code NODE_TAG_PREFIX} constant the cross-repo gate pins actually DRIVES the emitted
 *       tags, instead of being inert decoration a mutation cannot reach;</li>
 *   <li>{@link #aclsKeepTheK8sDataPlaneRule_neverEmpty()} — {@code acls[]} carries the
 *       10.244/10.96 rule instead of being empty (an empty push blanks cluster networking);</li>
 *   <li>{@link #superadminMeshRule_isAlwaysEmitted_evenForAnEmptyExport()} — the always-on
 *       superadmin reach to the core nodes the export omits;</li>
 *   <li>{@link #tagOwners_securityTagsDeclaredOwnerless_membershipTagsOwned()} and
 *       {@link #noSecurityTagHasAnOwner_forAnyExport()} — [FIX-SERVERTAG]: every security tag is
 *       declared with an EMPTY owner list, so no node can self-assign it;</li>
 *   <li>{@link #srcIsTheAdvisoryMembershipTag_noFictionalOperatorGroups()} — no
 *       {@code group:op-*} principals headscale does not know.</li>
 * </ul>
 * The pre-existing contract (deny-by-default, no wildcard, determinism, blank-entry drop) is
 * still asserted alongside.
 */
class HeadscaleAclCompilerTest {

    /** The compiler emits HuJSON (JSON + a leading {@code //} audit header) — parse it as such. */
    private final ObjectMapper mapper = JsonMapper.builder()
            .enable(JsonReadFeature.ALLOW_JAVA_COMMENTS)
            .build();

    private final HeadscaleAclCompiler compiler =
            new HeadscaleAclCompiler(new ObjectMapper(), "east-01", "superadmin");

    private static AuthorizedOperator op(String operator, String fp, String host) {
        return new AuthorizedOperator(operator, fp, host, List.of("SHA256:key-" + fp),
                AuthorizedOperator.VIA_DEVICE_LICENSE);
    }

    private static ExportBody body(long gen, AuthorizedOperator... ops) {
        return new ExportBody("mesh_default", gen, List.of(ops));
    }

    private static List<String> texts(JsonNode arrayNode) {
        List<String> out = new ArrayList<>();
        if (arrayNode != null) {
            arrayNode.forEach(n -> out.add(n.asText()));
        }
        return out;
    }

    /** Every ssh rule whose src is exactly {@code src}. */
    private static List<JsonNode> sshBySrc(JsonNode root, String src) {
        List<JsonNode> out = new ArrayList<>();
        root.get("ssh").forEach(r -> {
            if (texts(r.get("src")).equals(List.of(src))) {
                out.add(r);
            }
        });
        return out;
    }

    // ── RECONCILIATION: tag shape ────────────────────────────────────────────────

    @Test
    void nodeTag_isTheServerForcedDevTag_notTagNode() throws Exception {
        // Hashes pinned from the shell, NOT from devTagFor():
        //   printf '%s' 'FP-AAA' | openssl dgst -sha256 | awk '{print $NF}' | cut -c1-12
        String policy = compiler.compile(body(7,
                op("alice@x", "FP-AAA", "node-a"),
                op("alice@x", "FP-BBB", "node-b")));
        JsonNode root = mapper.readTree(policy);

        List<String> allDst = new ArrayList<>();
        root.get("ssh").forEach(r -> allDst.addAll(texts(r.get("dst"))));

        assertThat(allDst).contains("tag:dev_74d1e77ac6a8", "tag:dev_f277946101af");
        // The raw-fp shape no node has ever carried must be gone from the whole document.
        assertThat(policy).doesNotContain("tag:node-");
        assertThat(policy).doesNotContain("FP-AAA").doesNotContain("FP-BBB");
        assertThat(allDst).noneMatch(d -> d.contains("*"));
    }

    @Test
    void nodeTagPrefix_isLoadBearing_everyEmittedNodeTagIsBuiltFromIt() throws Exception {
        // REGRESSION (adversarial verification, 2026-07-30): NODE_TAG_PREFIX used to be inert.
        // nodeTagFor() spelled the tag a SECOND way (TAG_PREFIX + devTagFor(fp)), so the constant
        // could be pointed back at the dead "tag:node-" shape without changing one byte of the
        // compiled policy — all 39 tests stayed green while the gate's headline tag-shape
        // assertion pinned a value nothing read. These assertions bind the constant to the
        // EMISSION: they are stated in terms of NODE_TAG_PREFIX, so a constant that no longer
        // drives the output cannot satisfy them.
        String policy = compiler.compile(body(9,
                op("alice@x", "FP-AAA", "node-a"),
                op("bob@x", "FP-BBB", "node-b")));
        JsonNode root = mapper.readTree(policy);

        List<String> nodeDst = new ArrayList<>();
        sshBySrc(root, HeadscaleAclCompiler.ADVISORY_SRC_TAG)
                .forEach(r -> nodeDst.addAll(texts(r.get("dst"))));

        // 1. Every per-node ssh dst carries the constant as its prefix...
        assertThat(nodeDst).hasSize(2).allSatisfy(
                d -> assertThat(d).startsWith(HeadscaleAclCompiler.NODE_TAG_PREFIX));
        // 2. ...and so does every per-node tagOwners key [FIX-SERVERTAG].
        List<String> ownerKeys = new ArrayList<>();
        root.get("tagOwners").fieldNames().forEachRemaining(ownerKeys::add);
        assertThat(ownerKeys).containsAll(nodeDst);
        // 3. The constant composes exactly one way — the namespace plus the shell's bare prefix —
        //    so there is no second spelling for a refactor to drift back into.
        assertThat(HeadscaleAclCompiler.NODE_TAG_PREFIX)
                .isEqualTo(HeadscaleAclCompiler.TAG_PREFIX + HeadscaleAclCompiler.DEV_TAG_PREFIX);
        // 4. And the emitted tag is byte-for-byte the constant plus the shell hash (pinned
        //    literals, computed outside Java) — not merely "something that starts with it".
        assertThat(nodeDst).containsExactlyInAnyOrder(
                HeadscaleAclCompiler.NODE_TAG_PREFIX + "74d1e77ac6a8",
                HeadscaleAclCompiler.NODE_TAG_PREFIX + "f277946101af");
        assertThat(nodeDst).containsExactlyInAnyOrder("tag:dev_74d1e77ac6a8", "tag:dev_f277946101af");
    }

    @Test
    void devTagFor_matchesTheShellDevTagForFp_bytewise() {
        // The three implementations that MUST agree: gen-headscale-policy.sh:dev_tag_for_fp,
        // hugmesh-headscale-forcetags:dev_tag_for_fp, and this one.
        assertThat(HeadscaleAclCompiler.devTagFor("fpA")).isEqualTo("dev_084628ddb3aa");
        assertThat(HeadscaleAclCompiler.devTagFor("fpB")).isEqualTo("dev_29f12e1deee6");
        assertThat(HeadscaleAclCompiler.devTagFor("FP-A")).isEqualTo("dev_250fb2ed2cb3");
        assertThat(HeadscaleAclCompiler.devTagFor("")).isEqualTo("dev_e3b0c44298fc");
    }

    @Test
    void sanitiseTag_matchesTheShellSanitiseTag() {
        // tr lower | tr -c 'a-z0-9-' '-' | collapse runs | strip leading/trailing '-'
        assertThat(HeadscaleAclCompiler.sanitiseTag("east-01")).isEqualTo("east-01");
        assertThat(HeadscaleAclCompiler.sanitiseTag("mesh_default")).isEqualTo("mesh-default");
        assertThat(HeadscaleAclCompiler.sanitiseTag("East__01!")).isEqualTo("east-01");
        assertThat(HeadscaleAclCompiler.sanitiseTag("__lead-trail__")).isEqualTo("lead-trail");
    }

    // ── RECONCILIATION: the data-plane rule must survive ─────────────────────────

    @Test
    void aclsKeepTheK8sDataPlaneRule_neverEmpty() throws Exception {
        for (ExportBody b : List.of(body(0), body(7, op("alice@x", "FP-AAA", "node-a")))) {
            JsonNode root = mapper.readTree(compiler.compile(b));
            JsonNode acls = root.get("acls");
            assertThat(acls).hasSize(1);
            JsonNode rule = acls.get(0);
            assertThat(rule.get("action").asText()).isEqualTo("accept");
            assertThat(texts(rule.get("src"))).containsExactly("tag:hugmesh");
            assertThat(texts(rule.get("dst")))
                    .containsExactly("10.244.0.0/16:*", "10.96.0.0/12:*");
            // [FIX-DROPMESHRULE] the any-to-any :22 hole stays dropped.
            assertThat(texts(rule.get("dst"))).doesNotContain("tag:hugmesh:*");
            // The advertised subnet routes stay auto-approved, or the rule is inert.
            JsonNode routes = root.get("autoApprovers").get("routes");
            assertThat(texts(routes.get("10.244.0.0/16"))).containsExactly("tag:hugmesh");
            assertThat(texts(routes.get("10.96.0.0/12"))).containsExactly("tag:hugmesh");
        }
    }

    // ── RECONCILIATION: the always-on SUPERADMIN mesh rule ───────────────────────

    @Test
    void superadminMeshRule_isAlwaysEmitted_evenForAnEmptyExport() throws Exception {
        JsonNode root = mapper.readTree(compiler.compile(body(0)));
        // Empty export -> ssh[] is EXACTLY the superadmin mesh rule (renderer parity).
        assertThat(root.get("ssh")).hasSize(1);
        JsonNode sup = root.get("ssh").get(0);
        assertThat(texts(sup.get("src"))).containsExactly("tag:superadmin");
        assertThat(texts(sup.get("dst"))).containsExactly("tag:mesh_east-01");
        assertThat(texts(sup.get("users"))).containsExactly("superadmin");

        // And it stays FIRST when there are node edges.
        JsonNode withNodes = mapper.readTree(compiler.compile(body(3,
                op("alice@x", "FP-A", "na"), op("bob@y", "FP-B", "nb"))));
        assertThat(texts(withNodes.get("ssh").get(0).get("src")))
                .containsExactly("tag:superadmin");
        assertThat(sshBySrc(withNodes, "tag:superadmin")).hasSize(1);
    }

    // ── RECONCILIATION: ownerless security tags [FIX-SERVERTAG] ──────────────────

    /** The security-tag families: assigned only by the force-tagger, never self-advertised. */
    private static boolean isSecurityTag(String tag) {
        return tag.equals("tag:superadmin") || tag.startsWith("tag:mesh_")
                || tag.startsWith("tag:dev_") || tag.startsWith("tag:dom_");
    }

    @Test
    void tagOwners_securityTagsDeclaredOwnerless_membershipTagsOwned() throws Exception {
        // REGRESSION (2026-11-11): tag:superadmin and every tag:dev_<fp> were declared OWNED by
        // "hugmesh", the user every pre-auth key is minted for. headscale 0.23 grants a node
        // every advertised tag its user owns, so that shape let any node self-assign the tag.
        // hugmesh-generator #888/#896 removed it from the live writer; this compiler kept it.
        JsonNode root = mapper.readTree(compiler.compile(body(7,
                op("alice@x", "FP-AAA", "node-a"))));
        JsonNode owners = root.get("tagOwners");
        // Membership tags: self-applied by every node, so owned by the membership user.
        for (String t : List.of("tag:hugmesh", "tag:pki", "tag:be", "tag:fe", "tag:host")) {
            assertThat(texts(owners.get(t))).as(t).containsExactly("hugmesh");
        }
        // Security tags: DECLARED (key present, so headscale can build every node's map) with
        // the EMPTY owner list (so an advertisement lands in invalid_tags).
        for (String t : List.of("tag:superadmin", "tag:mesh_east-01", "tag:dev_74d1e77ac6a8")) {
            assertThat(owners.has(t)).as("%s must be declared", t).isTrue();
            assertThat(owners.get(t).isArray()).as("%s owner list is an array", t).isTrue();
            assertThat(texts(owners.get(t))).as("%s must have NO owner", t).isEmpty();
        }
        // Nothing else is declared: an extra owned key would be a tag someone can self-assign.
        List<String> keys = new ArrayList<>();
        owners.fieldNames().forEachRemaining(keys::add);
        assertThat(keys).containsExactlyInAnyOrder("tag:hugmesh", "tag:pki", "tag:be", "tag:fe",
                "tag:host", "tag:superadmin", "tag:mesh_east-01", "tag:dev_74d1e77ac6a8");
        // EVERY tag an ssh rule names (src or dst) is declared, and every one of them is a
        // security tag or the advisory membership src.
        root.get("ssh").forEach(rule -> {
            List<String> named = new ArrayList<>(texts(rule.get("src")));
            named.addAll(texts(rule.get("dst")));
            named.forEach(tag -> {
                assertThat(owners.has(tag)).as("ssh names %s, which must be declared", tag).isTrue();
                if (isSecurityTag(tag)) {
                    assertThat(texts(owners.get(tag))).as("ssh tag %s must have NO owner", tag)
                            .isEmpty();
                }
            });
        });
    }

    @Test
    void noSecurityTagHasAnOwner_forAnyExport() throws Exception {
        // The invariant over every shape the compiler is fed, independent of the shared golden:
        // empty, null, one node, the de-dup path, many nodes, and the back-compat constructor.
        List<ExportBody> bodies = new ArrayList<>();
        bodies.add(null);
        bodies.add(body(0));
        bodies.add(body(1, op("alice@x", "FP-A", "na")));
        bodies.add(body(2, op("alice@x", "FP-DUP", "n"), op("bob@y", "FP-DUP", "n")));
        AuthorizedOperator[] many = new AuthorizedOperator[12];
        for (int i = 0; i < many.length; i++) {
            many[i] = op("op" + i + "@x", "FP-" + i, "n" + i);
        }
        bodies.add(body(3, many));
        for (HeadscaleAclCompiler c : List.of(compiler, new HeadscaleAclCompiler(new ObjectMapper()),
                new HeadscaleAclCompiler(new ObjectMapper(), "Other Mesh!", "root"))) {
            for (ExportBody b : bodies) {
                JsonNode owners = mapper.readTree(c.compile(b)).get("tagOwners");
                List<String> security = new ArrayList<>();
                owners.fieldNames().forEachRemaining(tag -> {
                    if (isSecurityTag(tag)) {
                        security.add(tag);
                        assertThat(texts(owners.get(tag))).as("security tag %s has an owner", tag)
                                .isEmpty();
                    } else {
                        // Literals, not the compiler's constants, so the test cannot agree
                        // with a wrong implementation by construction.
                        assertThat(List.of("tag:hugmesh", "tag:pki", "tag:be", "tag:fe",
                                "tag:host")).as("%s is neither a membership nor a security tag",
                                tag).contains(tag);
                        assertThat(texts(owners.get(tag))).as(tag).containsExactly("hugmesh");
                    }
                });
                // tag:superadmin and the mesh tag are declared for every export, empty included.
                assertThat(security).contains(HeadscaleAclCompiler.SUPERADMIN_TAG);
                assertThat(security).anyMatch(t -> t.startsWith("tag:mesh_"));
            }
        }
    }

    // ── RECONCILIATION: advisory src, no fictional operator groups ───────────────

    @Test
    void srcIsTheAdvisoryMembershipTag_noFictionalOperatorGroups() throws Exception {
        String policy = compiler.compile(body(3,
                op("alice@x", "FP-A", "na"), op("bob@y", "FP-B", "nb")));
        JsonNode root = mapper.readTree(policy);

        // No group:* principals and no Casdoor subjects leak into the tailnet policy.
        assertThat(root.get("groups")).isNull();
        assertThat(policy).doesNotContain("group:op-");
        assertThat(policy).doesNotContain("alice@x").doesNotContain("bob@y");

        // Every node edge is src=tag:hugmesh (advisory; FIX-OIDC-USERS deferred).
        assertThat(sshBySrc(root, "tag:hugmesh")).hasSize(2);
    }

    // ── Pre-existing contract, still enforced ────────────────────────────────────

    @Test
    void emptyExport_compilesToRendererMinimum_notWildcard_notCleared() throws Exception {
        String policy = compiler.compile(body(0));
        JsonNode root = mapper.readTree(policy);

        assertThat(root.get("ssh").isArray()).isTrue();
        assertThat(root.get("ssh")).hasSize(1);              // the superadmin mesh rule only
        assertThat(root.get("acls")).hasSize(1);             // the CIDR data-plane rule only
        // No tag wildcard anywhere; the only "*" is the CIDR port wildcard.
        assertThat(policy).doesNotContain("\"*\"");
        assertThat(policy).doesNotContain("tag:hugmesh:*");
    }

    @Test
    void oneEdgePerNode_dedupedAcrossOperatorsAndLicenses() throws Exception {
        // Same node reached by two operators AND two license kinds -> ONE edge, ONE dst tag.
        JsonNode root = mapper.readTree(compiler.compile(body(2,
                op("alice@x", "FP-DUP", "n"),
                new AuthorizedOperator("alice@x", "FP-DUP", "n", List.of("SHA256:k2"),
                        AuthorizedOperator.VIA_DOMAIN_LICENSE),
                op("bob@y", "FP-DUP", "n"))));
        List<JsonNode> nodeEdges = sshBySrc(root, "tag:hugmesh");
        assertThat(nodeEdges).hasSize(1);
        assertThat(texts(nodeEdges.get(0).get("dst"))).containsExactly("tag:dev_d6c17646745a");
    }

    @Test
    void twoOperators_bothNodesReachable_eachExactlyOnce() throws Exception {
        JsonNode root = mapper.readTree(compiler.compile(body(3,
                op("alice@x", "FP-A", "na"),
                op("bob@y", "FP-B", "nb"))));
        List<JsonNode> nodeEdges = sshBySrc(root, "tag:hugmesh");
        assertThat(nodeEdges).hasSize(2);
        List<String> dst = new ArrayList<>();
        nodeEdges.forEach(r -> dst.addAll(texts(r.get("dst"))));
        assertThat(dst).containsExactly("tag:dev_250fb2ed2cb3", "tag:dev_de2fb9fcfb97");
    }

    @Test
    void compile_isDeterministic_regardlessOfInputOrder() {
        ExportBody ordered = body(9, op("alice@x", "FP-1", "n1"), op("bob@y", "FP-2", "n2"));
        ExportBody shuffled = body(9, op("bob@y", "FP-2", "n2"), op("alice@x", "FP-1", "n1"));

        assertThat(compiler.compile(ordered)).isEqualTo(compiler.compile(shuffled));
    }

    @Test
    void blankOperatorOrFp_isDropped_failClosed() throws Exception {
        JsonNode root = mapper.readTree(compiler.compile(body(1,
                new AuthorizedOperator("", "FP-X", "n", List.of("k"), AuthorizedOperator.VIA_DEVICE_LICENSE),
                new AuthorizedOperator("alice@x", "", "n", List.of("k"), AuthorizedOperator.VIA_DEVICE_LICENSE),
                op("real@x", "FP-OK", "n"))));
        List<JsonNode> nodeEdges = sshBySrc(root, "tag:hugmesh");
        assertThat(nodeEdges).hasSize(1);
        assertThat(texts(nodeEdges.get(0).get("dst"))).containsExactly("tag:dev_e2bd7072e18f");
    }

    @Test
    void generation_isCarriedInComment_forAudit() {
        String policy = compiler.compile(body(42, op("a@x", "FP", "n")));
        assertThat(policy).startsWith("// hugmesh device-license export");
        assertThat(policy).contains("generation=42").contains("mesh=mesh_default");
    }

    @Test
    void nullBody_compilesToRendererMinimum_neverThrows() throws Exception {
        JsonNode root = mapper.readTree(compiler.compile(null));
        assertThat(root.get("ssh")).hasSize(1);      // superadmin mesh rule survives a null body
        assertThat(root.get("acls")).hasSize(1);     // and so does the data-plane rule
    }

    @Test
    void defaultConstructor_usesTheRenderersOwnFallbacks() throws Exception {
        // provision.sh resolve_ssh_user falls back to "admin"; mesh default is mesh_default.
        JsonNode root = mapper.readTree(new HeadscaleAclCompiler(new ObjectMapper()).compile(body(0)));
        JsonNode sup = root.get("ssh").get(0);
        assertThat(texts(sup.get("dst"))).containsExactly("tag:mesh_mesh-default");
        assertThat(texts(sup.get("users"))).containsExactly("admin");
    }
}
