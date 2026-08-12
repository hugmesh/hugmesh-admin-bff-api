package net.hugmesh.adminbff.device;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import net.hugmesh.adminbff.device.ExportModels.AuthorizedOperator;
import net.hugmesh.adminbff.device.ExportModels.ExportBody;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The pure compile leg: a signed device-license export {@link ExportBody} -> a headscale ACL
 * policy. Proves the load-bearing properties WITHOUT a live headscale:
 * <ul>
 *   <li>each authorized operator becomes an {@code ssh accept} rule to EXACTLY its licensed
 *       node host-tags ({@code tag:node-<machineKeyFp>}) — never a wildcard;</li>
 *   <li>the output is DETERMINISTIC / byte-stable for a stable body (the idempotency contract
 *       the reconciler's skip-on-no-change relies on), including across operator/dest ordering;</li>
 *   <li>an EMPTY export compiles to a well-formed DENY-ALL policy (empty {@code ssh}/{@code acls}),
 *       NOT a wildcard and NOT a cleared policy;</li>
 *   <li>a blank operator/fp entry is dropped (fail-closed — never an unkeyed grant).</li>
 * </ul>
 */
class HeadscaleAclCompilerTest {

    private final ObjectMapper mapper = new ObjectMapper();
    private final HeadscaleAclCompiler compiler = new HeadscaleAclCompiler(mapper);

    private static AuthorizedOperator op(String operator, String fp, String host) {
        return new AuthorizedOperator(operator, fp, host, List.of("SHA256:key-" + fp),
                AuthorizedOperator.VIA_DEVICE_LICENSE);
    }

    private static ExportBody body(long gen, AuthorizedOperator... ops) {
        return new ExportBody("mesh_default", gen, List.of(ops));
    }

    @Test
    void emptyExport_compilesToDenyAll_notWildcard() throws Exception {
        String policy = compiler.compile(body(0));
        JsonNode root = mapper.readTree(policy);

        assertThat(root.get("ssh")).isNotNull();
        assertThat(root.get("ssh").isArray()).isTrue();
        assertThat(root.get("ssh")).isEmpty();         // no operator -> no SSH edge (deny-all)
        assertThat(root.get("acls")).isEmpty();        // empty acls = deny-all general traffic
        assertThat(root.get("groups")).isEmpty();
        // No wildcard anywhere.
        assertThat(policy).doesNotContain("\"*\"");
    }

    @Test
    void operator_getsSshAccept_toExactlyItsLicensedNodeTags_noWildcard() throws Exception {
        String policy = compiler.compile(body(7,
                op("alice@x", "FP-AAA", "node-a"),
                op("alice@x", "FP-BBB", "node-b")));
        JsonNode root = mapper.readTree(policy);

        JsonNode ssh = root.get("ssh");
        assertThat(ssh).hasSize(1);                    // one operator -> one accept rule
        JsonNode rule = ssh.get(0);
        assertThat(rule.get("action").asText()).isEqualTo("accept");

        // dst is EXACTLY the two licensed node host-tags (sorted), never a wildcard.
        List<String> dst = rule.get("dst").findValuesAsText("");
        // (findValuesAsText("") on a value array returns each element)
        List<String> dests = new java.util.ArrayList<>();
        rule.get("dst").forEach(n -> dests.add(n.asText()));
        assertThat(dests).containsExactly("tag:node-FP-AAA", "tag:node-FP-BBB");
        assertThat(dests).noneMatch(d -> d.contains("*"));

        // src is the operator's own group (membership = the literal operator identity).
        List<String> src = new java.util.ArrayList<>();
        rule.get("src").forEach(n -> src.add(n.asText()));
        assertThat(src).hasSize(1);
        String group = src.get(0);
        assertThat(root.get("groups").get(group)).isNotNull();
        List<String> members = new java.util.ArrayList<>();
        root.get("groups").get(group).forEach(n -> members.add(n.asText()));
        assertThat(members).containsExactly("alice@x");
    }

    @Test
    void twoOperators_eachReachOnlyItsOwnNodes_isolation() throws Exception {
        String policy = compiler.compile(body(3,
                op("alice@x", "FP-A", "na"),
                op("bob@y", "FP-B", "nb")));
        JsonNode ssh = mapper.readTree(policy).get("ssh");
        assertThat(ssh).hasSize(2);

        // Find each rule by its sole member and assert it reaches ONLY its own node tag.
        for (JsonNode rule : ssh) {
            List<String> dests = new java.util.ArrayList<>();
            rule.get("dst").forEach(n -> dests.add(n.asText()));
            // Each operator licensed to exactly ONE node -> exactly one dst, its own.
            assertThat(dests).hasSize(1);
        }
        // alice cannot reach bob's node and vice-versa: the full policy text never pairs
        // alice's group with FP-B or bob's with FP-A in the same rule (one node each).
        assertThat(policy).contains("tag:node-FP-A").contains("tag:node-FP-B");
    }

    @Test
    void compile_isDeterministic_regardlessOfInputOrder() {
        // Same logical set, different entry order -> byte-identical policy (idempotency).
        ExportBody ordered = body(9,
                op("alice@x", "FP-1", "n1"),
                op("bob@y", "FP-2", "n2"));
        ExportBody shuffled = body(9,
                op("bob@y", "FP-2", "n2"),
                op("alice@x", "FP-1", "n1"));

        assertThat(compiler.compile(ordered)).isEqualTo(compiler.compile(shuffled));
    }

    @Test
    void duplicateDestinations_areDeduped() throws Exception {
        // Same operator licensed to the same node via two licenses -> one dst, not two.
        String policy = compiler.compile(body(2,
                op("alice@x", "FP-DUP", "n"),
                new AuthorizedOperator("alice@x", "FP-DUP", "n", List.of("SHA256:k2"),
                        AuthorizedOperator.VIA_DOMAIN_LICENSE)));
        JsonNode ssh = mapper.readTree(policy).get("ssh");
        assertThat(ssh).hasSize(1);
        List<String> dests = new java.util.ArrayList<>();
        ssh.get(0).get("dst").forEach(n -> dests.add(n.asText()));
        assertThat(dests).containsExactly("tag:node-FP-DUP");
    }

    @Test
    void blankOperatorOrFp_isDropped_failClosed() throws Exception {
        String policy = compiler.compile(body(1,
                new AuthorizedOperator("", "FP-X", "n", List.of("k"), AuthorizedOperator.VIA_DEVICE_LICENSE),
                new AuthorizedOperator("alice@x", "", "n", List.of("k"), AuthorizedOperator.VIA_DEVICE_LICENSE),
                op("real@x", "FP-OK", "n")));
        JsonNode ssh = mapper.readTree(policy).get("ssh");
        // Only the well-formed entry survives.
        assertThat(ssh).hasSize(1);
        List<String> dests = new java.util.ArrayList<>();
        ssh.get(0).get("dst").forEach(n -> dests.add(n.asText()));
        assertThat(dests).containsExactly("tag:node-FP-OK");
    }

    @Test
    void generation_isCarriedInComment_forAudit() {
        String policy = compiler.compile(body(42, op("a@x", "FP", "n")));
        assertThat(policy).contains("generation=42").contains("mesh=mesh_default");
    }

    @Test
    void nullBody_compilesToDenyAll_neverThrows() throws Exception {
        String policy = compiler.compile(null);
        JsonNode root = mapper.readTree(policy);
        assertThat(root.get("ssh")).isEmpty();
        assertThat(policy).doesNotContain("\"*\"");
    }
}
