package systems.hugmesh.adminbff.device;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import systems.hugmesh.adminbff.device.ExportModels.AuthorizedOperator;
import systems.hugmesh.adminbff.device.ExportModels.ExportBody;

import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;

/**
 * Compiles the UNSCOPED signed device-license export {@link ExportBody} into a headscale ACL
 * POLICY document (HuJSON-compatible JSON) — the Layer-A leg that turns each compiled
 * {@link AuthorizedOperator} entry into a permitted headscale SSH edge. The READ side
 * ({@link HeadscaleNodesClient}) reads enrolled nodes; the export
 * ({@code DeviceRegistryExportService}) compiles the AUTH PREDICATE into authorized operators;
 * THIS compiler emits the headscale {@code ssh} rules that grant exactly those operators
 * {@code accept}-SSH to exactly the nodes they are licensed for, keyed by the node's stable
 * {@code machine_key_fp} (host-tag {@code tag:node-<fp>}).
 *
 * <h3>Pure + deterministic (so the push is IDEMPOTENT)</h3>
 * No IO; given the same export body it emits BYTE-IDENTICAL policy text (sorted host-tag and
 * source sets, stable field order via Jackson {@link ObjectNode} insertion). The reconcile loop
 * relies on that: it compiles, compares to the last-pushed text, and PUSHES ONLY ON CHANGE — a
 * stable export yields a stable policy yields a skipped no-op PUT.
 *
 * <h3>Conservative, default-DENY shape</h3>
 * The export is ALREADY the default-deny compiled allow-set (no entry → no access). This
 * compiler does NOT invent any rule the export did not authorize:
 * <ul>
 *   <li>only operators that appear in {@code operators[]} get an {@code ssh} accept rule;</li>
 *   <li>each operator's destinations are EXACTLY the {@code tag:node-<machineKeyFp>} of the
 *       nodes the export listed for them — never a wildcard;</li>
 *   <li>an EMPTY export compiles to a policy with EMPTY {@code ssh}/{@code acls} (deny-all) —
 *       NOT a wildcard and NOT a cleared policy, so pushing it neither widens nor blanks the
 *       mesh (the reconciler additionally refuses to push an empty body, defense-in-depth).</li>
 * </ul>
 * The {@code via}/role concerns stay where the export left them: this is PROVENANCE-blind, it
 * only re-expresses the already-decided allow-set as headscale's policy language. The host-tag
 * naming + the unverified {@code machine_key_fp} canonical-field caveat are inherited from the
 * export (see {@code docs/CANONICAL-FP.md}) — which is WHY the whole leg ships dark.
 */
public final class HeadscaleAclCompiler {

    /** The host-tag prefix a node is addressed by in the compiled policy: {@code tag:node-<fp>}. */
    static final String NODE_TAG_PREFIX = "tag:node-";

    private final ObjectMapper mapper;

    public HeadscaleAclCompiler(ObjectMapper mapper) {
        this.mapper = mapper;
    }

    /**
     * Compile {@code body} into the headscale ACL policy text (HuJSON-compatible JSON). Stable
     * for a stable body. Never null; an empty/whitespace-only export yields a well-formed
     * deny-all policy (empty {@code acls}/{@code ssh}, empty {@code groups}/{@code hosts}).
     */
    public String compile(ExportBody body) {
        ObjectNode root = mapper.createObjectNode();

        // Header comment carrying the generation — for human/audit inspection of the live policy.
        // (HuJSON tolerates // comments; we keep it as a plain field so strict-JSON readers also
        //  parse it, and so the content is deterministic.)
        long generation = body == null ? 0L : body.generation();
        String meshId = (body == null || body.meshId() == null) ? "" : body.meshId();
        root.put("$comment",
                "hugmesh device-license export -> headscale ACL; mesh=" + meshId
                        + " generation=" + generation + " (compiled, do not hand-edit)");

        // groups{}: one per operator -> ["<operator>"]. Deterministic (TreeMap-ordered keys).
        ObjectNode groups = mapper.createObjectNode();
        // hosts{}: reserved for future host CIDRs; empty but present for a stable shape.
        ObjectNode hosts = mapper.createObjectNode();
        // acls[]: kept empty — SSH reach is expressed entirely via ssh[] (headscale's
        // tailnet-SSH policy). An empty acls[] is deny-all for general traffic.
        ArrayNode acls = mapper.createArrayNode();
        // ssh[]: one accept rule per operator -> their licensed node host-tags.
        ArrayNode ssh = mapper.createArrayNode();

        List<AuthorizedOperator> operators = (body == null) ? List.of() : body.operators();

        // Index operator -> sorted set of destination host-tags (dedup + deterministic order).
        // Use a TreeSet of operators so groups/ssh come out in a stable operator order.
        Set<String> operatorOrder = new TreeSet<>();
        var destsByOperator = new TreeMap<String, Set<String>>();
        for (AuthorizedOperator op : operators) {
            String operator = nz(op.operator());
            String fp = nz(op.machineKeyFp());
            if (operator.isEmpty() || fp.isEmpty()) {
                // The export should never emit a blank operator/fp; skip defensively (fail-closed
                // — a malformed entry must not become a wildcard or an unkeyed grant).
                continue;
            }
            operatorOrder.add(operator);
            destsByOperator.computeIfAbsent(operator, k -> new TreeSet<>())
                    .add(NODE_TAG_PREFIX + fp);
        }

        for (String operator : operatorOrder) {
            String group = "group:op-" + sanitize(operator);
            ArrayNode members = mapper.createArrayNode();
            members.add(operator);
            groups.set(group, members);

            ArrayNode sources = mapper.createArrayNode();
            sources.add(group);
            ArrayNode destinations = mapper.createArrayNode();
            // De-dup already handled by the TreeSet; preserve its sorted order.
            Set<String> dests = destsByOperator.getOrDefault(operator, new LinkedHashSet<>());
            for (String d : dests) {
                destinations.add(d);
            }

            ObjectNode rule = mapper.createObjectNode();
            rule.put("action", "accept");
            rule.set("src", sources);
            rule.set("dst", destinations);
            // Permit interactive SSH as the node-local operator user; headscale checks the
            // tailnet identity, the per-node sshd (Layer-B) still independently re-derives role
            // and pins the exact key fingerprints — this rule only opens the headscale edge.
            ArrayNode users = mapper.createArrayNode();
            users.add("autogroup:nonroot");
            rule.set("users", users);
            ssh.add(rule);
        }

        root.set("groups", groups);
        root.set("hosts", hosts);
        root.set("acls", acls);
        root.set("ssh", ssh);

        try {
            // Pretty + stable: Jackson preserves insertion order; sets above are sorted, so the
            // output is byte-identical for an identical body (the idempotency contract).
            return mapper.writerWithDefaultPrettyPrinter().writeValueAsString(root);
        } catch (JsonProcessingException e) {
            // Never expected for an ObjectNode tree; surface as empty so the reconciler refuses
            // to push (fail-closed) rather than pushing a half-baked body.
            throw new IllegalStateException("headscale ACL compile failed", e);
        }
    }

    /** headscale group names allow a restricted charset; map anything else to '-' so the
     *  group key is always valid + deterministic. The operator literal inside the group
     *  members[] is left verbatim (that is the matched identity). */
    private static String sanitize(String s) {
        StringBuilder b = new StringBuilder(s.length());
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            b.append((Character.isLetterOrDigit(c) || c == '-' || c == '.') ? c : '-');
        }
        return b.toString();
    }

    private static String nz(String s) {
        return s == null ? "" : s;
    }
}
