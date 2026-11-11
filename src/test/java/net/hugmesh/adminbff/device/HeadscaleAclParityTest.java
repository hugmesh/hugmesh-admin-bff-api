package net.hugmesh.adminbff.device;

import com.fasterxml.jackson.core.json.JsonReadFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.json.JsonMapper;
import org.junit.jupiter.api.Test;
import net.hugmesh.adminbff.device.ExportModels.ExportBody;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * FULL-DOCUMENT CROSS-WRITER PARITY — the strongest assertion in the Layer-A contract.
 *
 * <h3>Why this test exists</h3>
 * Layer-A has had TWO writers of ONE headscale policy:
 * <ul>
 *   <li>the NODE-side renderer, {@code hugmesh-generator}
 *       {@code specs/usr/sbin/gen-headscale-policy.sh} — RETIRED as a writer by decision
 *       101 = B (2026-09-23), but still what the fleet as built runs on every control node (file
 *       mode, the {@code hugmesh-policy-sync} cron) until the generator cut-over lands; and</li>
 *   <li>this BFF's {@link HeadscaleAclCompiler} + reconcile loop — the decided SOLE writer,
 *       still DARK behind {@code app.registry.headscale-acl.enabled=false}.</li>
 * </ul>
 * The cut-over swaps writer #2 in for writer #1. That is only safe if, for the same signed
 * export, they describe the SAME mesh — so this parity is the cut-over contract, and it stays
 * pinned until the node renderer is actually gone. Until 2026-07-30 they did not:
 * the compiler addressed nodes by {@code tag:node-<raw fp>} (a tag no node carries), emitted an
 * empty {@code acls[]} (which would have blanked the k8s data-plane rule fleet-wide), dropped the
 * always-on SUPERADMIN mesh rule, omitted {@code tagOwners}, and named {@code group:op-*}
 * principals headscale has never heard of.
 *
 * <h3>How it is proven, offline, in both repos</h3>
 * Structural assertions (does the source mention {@code tag:dev_}?) can only ever approximate
 * this. So the contract is pinned as a SHARED GOLDEN DOCUMENT instead:
 * <ol>
 *   <li>{@code layer-a-parity-export.json} — one canonical signed export (it deliberately lists
 *       the SAME node under two operators, so the de-duplication path is exercised);</li>
 *   <li>{@code layer-a-parity-params.env} — the two render inputs that live outside the export
 *       ({@code MESH_ID}, {@code TS_SSH_USER});</li>
 *   <li>{@code layer-a-parity-policy.golden.json} — the policy the NODE-SIDE SHELL RENDERER
 *       actually produces for that input, captured via {@code jq -S}.</li>
 * </ol>
 * All three files exist in BOTH repos:
 * {@code hugmesh-generator tests/device-registry/fixtures/} and (byte-identical copies)
 * {@code hugmesh-admin-bff-api src/test/resources/layer-a/}. THIS test asserts the Java compiler
 * reproduces the golden; the generator's {@code tests/device-registry/test-layer-a-headscale-acl.sh}
 * asserts the shell renderer still reproduces it AND that the two copies have not drifted apart.
 * Neither repo needs the other's toolchain — no JVM in the shell gate, no shell here.
 *
 * <p>Consequence: a change to either writer that alters ONE FIELD of the emitted policy fails a
 * gate in the repo that made it.
 */
class HeadscaleAclParityTest {

    /** The compiler emits HuJSON (JSON + a leading {@code //} audit header) — parse it as such. */
    private final ObjectMapper hujson = JsonMapper.builder()
            .enable(JsonReadFeature.ALLOW_JAVA_COMMENTS)
            .build();

    private static InputStream resource(String name) {
        InputStream in = HeadscaleAclParityTest.class.getResourceAsStream("/layer-a/" + name);
        assertThat(in).as("fixture /layer-a/%s must be on the test classpath", name).isNotNull();
        return in;
    }

    private static String param(String key) throws Exception {
        Properties p = new Properties();
        try (InputStream in = resource("layer-a-parity-params.env")) {
            p.load(in);
        }
        String v = p.getProperty(key);
        assertThat(v).as("%s must be declared in the shared parity params", key).isNotBlank();
        return v;
    }

    @Test
    void compiledPolicy_isIdenticalToWhatTheNodeSideRendererProduces() throws Exception {
        // The two render inputs that are NOT carried by the signed export. Read from the SAME
        // shared file the shell gate sources, so they cannot drift.
        String meshId = param("MESH_ID");
        String sshUser = param("TS_SSH_USER");

        ExportBody body;
        try (InputStream in = resource("layer-a-parity-export.json")) {
            // The fixture is the full signed envelope; the compiler consumes `.body`.
            JsonNode envelope = hujson.readTree(in);
            body = hujson.treeToValue(envelope.get("body"), ExportBody.class);
        }
        assertThat(body.operators())
                .as("the fixture must exercise the de-dup path (one node, two operators)")
                .hasSize(3);

        JsonNode compiled = hujson.readTree(
                new HeadscaleAclCompiler(new ObjectMapper(), meshId, sshUser).compile(body));

        JsonNode golden;
        try (InputStream in = resource("layer-a-parity-policy.golden.json")) {
            golden = hujson.readTree(new String(in.readAllBytes(), StandardCharsets.UTF_8));
        }

        // JsonNode equality is order-insensitive for objects and order-SENSITIVE for arrays —
        // exactly the semantics wanted here: tagOwners key order is irrelevant, but the ssh[]
        // ordering (SUPERADMIN rule FIRST, then fingerprint-sorted node edges) is part of the
        // contract and is pinned.
        assertThat(compiled)
                .as("the DARK BFF compiler must emit byte-equivalent policy to the LIVE node-side "
                        + "renderer (golden captured from gen-headscale-policy.sh). A diff here is "
                        + "what the live mesh would BECOME the moment someone enables the push.")
                .isEqualTo(golden);
    }

    @Test
    void goldenItself_carriesTheFourReconciledProperties() throws Exception {
        JsonNode golden;
        try (InputStream in = resource("layer-a-parity-policy.golden.json")) {
            golden = hujson.readTree(new String(in.readAllBytes(), StandardCharsets.UTF_8));
        }
        // A golden regenerated from a REGRESSED renderer must not be able to quietly relax the
        // contract, so the properties are asserted about the golden too, not only against it.

        // (b) node dst tags are the SERVER-FORCED tag:dev_<hash>, never tag:node-<raw fp>.
        assertThat(golden.toString()).doesNotContain("tag:node-");
        assertThat(golden.get("ssh")).anySatisfy(
                r -> assertThat(r.get("dst").get(0).asText()).startsWith("tag:dev_"));

        // (c) the k8s data-plane rule survives — acls[] is NOT empty.
        assertThat(golden.get("acls")).hasSize(1);
        assertThat(golden.get("acls").get(0).get("dst").toString())
                .contains("10.244.0.0/16:*").contains("10.96.0.0/12:*");

        // the always-on SUPERADMIN mesh rule is FIRST.
        assertThat(golden.get("ssh").get(0).get("src").get(0).asText()).isEqualTo("tag:superadmin");
        assertThat(golden.get("ssh").get(0).get("dst").get(0).asText()).startsWith("tag:mesh_");

        // [FIX-SERVERTAG] every security tag the document names is DECLARED with the EMPTY
        // owner list, and the membership tags stay owned by the membership user.
        //
        // History, because the golden itself once carried the hole: until 2026-11-11 this file's
        // copy of the golden (and this compiler) gave tag:superadmin and every tag:dev_<fp> the
        // owner "hugmesh", the user every pre-auth key is minted for. headscale 0.23 grants a
        // node every advertised tag its user owns, so that let any node self-assign the tag.
        // hugmesh-generator #888/#896 fixed the live writer and its golden; this copy was not
        // re-synced, and the cross-repo byte-identity check that would have said so did not run
        // in CI. The same change closed the old `tag:mesh_<id>` carve-out: the renderer now
        // declares the mesh tag (ownerless), so a missing declaration is a failure here too.
        JsonNode tagOwners = golden.get("tagOwners");
        for (String t : List.of("tag:hugmesh", "tag:pki", "tag:be", "tag:fe", "tag:host")) {
            assertThat(tagOwners.get(t)).as("membership tag %s must be declared", t).isNotNull();
            assertThat(tagOwners.get(t).toString()).as(t).isEqualTo("[\"hugmesh\"]");
        }
        List<String> named = new ArrayList<>();
        golden.get("ssh").forEach(rule -> {
            rule.get("src").forEach(n -> named.add(n.asText()));
            rule.get("dst").forEach(n -> named.add(n.asText()));
        });
        assertThat(named).contains("tag:superadmin").anyMatch(t -> t.startsWith("tag:mesh_"));
        for (String tag : named) {
            if (tag.equals("tag:hugmesh")) {
                continue;   // the advisory membership src, asserted owned above
            }
            assertThat(tagOwners.has(tag)).as("ssh names %s, which must be declared", tag).isTrue();
            assertThat(tagOwners.get(tag).isArray() && tagOwners.get(tag).isEmpty())
                    .as("security tag %s must have the EMPTY owner list, got %s", tag,
                            tagOwners.get(tag))
                    .isTrue();
        }
        tagOwners.fieldNames().forEachRemaining(tag -> {
            if (tag.equals("tag:superadmin") || tag.startsWith("tag:mesh_")
                    || tag.startsWith("tag:dev_") || tag.startsWith("tag:dom_")) {
                assertThat(tagOwners.get(tag).isEmpty())
                        .as("security tag %s must have NO owner, got %s", tag, tagOwners.get(tag))
                        .isTrue();
            }
        });

        // [FIX-OIDC-USERS] no principals headscale does not know.
        assertThat(golden.toString()).doesNotContain("group:op-");
        // [FIX-DROPMESHRULE] the any-to-any :22 hole stays gone.
        assertThat(golden.toString()).doesNotContain("tag:hugmesh:*");
    }
}
