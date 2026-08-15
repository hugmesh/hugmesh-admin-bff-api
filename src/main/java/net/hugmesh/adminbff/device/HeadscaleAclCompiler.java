package net.hugmesh.adminbff.device;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import net.hugmesh.adminbff.device.ExportModels.AuthorizedOperator;
import net.hugmesh.adminbff.device.ExportModels.ExportBody;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.TreeSet;

/**
 * Compiles the UNSCOPED signed device-license export {@link ExportBody} into a headscale ACL
 * POLICY document (HuJSON) — the Layer-A leg that turns each compiled
 * {@link AuthorizedOperator} entry into a permitted headscale SSH edge. The READ side
 * ({@code HeadscaleNodesClient}) reads enrolled nodes; the export
 * ({@code DeviceRegistryExportService}) compiles the AUTH PREDICATE into authorized operators;
 * THIS compiler emits the headscale policy that grants SSH to exactly the licensed nodes.
 *
 * <h3>⚠ THE NODE-SIDE RENDERER IS THE LIVE WRITER — THIS COMPILER MIRRORS IT</h3>
 * Layer-A already ships and RUNS on every control node: {@code hugmesh-generator}
 * {@code specs/usr/sbin/gen-headscale-policy.sh} renders {@code /etc/headscale/policy.hujson}
 * from {@code specs/etc/headscale/policy.hujson.tmpl} off the SAME signed export and applies it
 * with {@code headscale policy set -f} (headscale runs {@code policy: mode: file}). This
 * compiler is the DARK would-be replacement writer. It is therefore held to ONE contract:
 * <b>for the same export body it must describe the SAME mesh the node renderer describes</b>.
 * Any divergence is not a stylistic difference — it is what the live mesh would become the
 * moment somebody flips {@code app.registry.headscale-acl.enabled=true}.
 *
 * <p>Until 2026-07-30 the compiler diverged in FIVE load-bearing ways, each of which would have
 * broken the live mesh on the first push (all reconciled here; the offline gate
 * {@code tests/device-registry/test-layer-a-headscale-acl.sh} in hugmesh-generator now asserts
 * every one of them against this file):
 * <ol>
 *   <li><b>TAG SHAPE.</b> It addressed nodes as {@code tag:node-<raw machineKeyFp>}. Nodes are
 *       SERVER-FORCED {@code tag:dev_<sha256(fp)[0:12]>} by
 *       {@code specs/usr/sbin/hugmesh-headscale-forcetags} (and the renderer keys its ssh dst on
 *       that). {@code tag:node-*} is carried by NO node — every SSH edge would have been dead.
 *       See {@link #devTagFor(String)}, the byte-for-byte Java twin of the shell
 *       {@code dev_tag_for_fp}.</li>
 *   <li><b>EMPTY {@code acls[]}.</b> It emitted {@code "acls": []} "because SSH reach is
 *       expressed via ssh[]" — but the node policy KEEPS the k8s pod/ClusterIP data-plane rule
 *       ({@code 10.244.0.0/16} + {@code 10.96.0.0/12}) that makes pods and ClusterIPs reachable
 *       cross-node "as one LAN". Pushing an empty {@code acls[]} would have blanked cluster
 *       networking fleet-wide. Now emitted verbatim, together with the {@code autoApprovers}
 *       that keep those two advertised subnet routes auto-approved.</li>
 *   <li><b>NO SUPERADMIN MESH RULE.</b> The renderer ALWAYS emits
 *       {@code src:[tag:superadmin] dst:[tag:mesh_<id>]} — independent of the export body —
 *       because that is the ONLY reach superadmin has to the core/control nodes the export
 *       deliberately omits. Its absence would have locked superadmin out of exactly the nodes
 *       needed to recover.</li>
 *   <li><b>NO {@code tagOwners}.</b> [FIX-SERVERTAG] requires every security dst tag to be
 *       declared control-owned so no node can self-advertise it. A policy without
 *       {@code tagOwners} re-opens the masquerade hole the force-tagger closed.</li>
 *   <li><b>FICTIONAL SRC IDENTITY.</b> It emitted {@code src:["group:op-<operator>"]} with the
 *       Casdoor subject as the group member. headscale has NO per-operator tailnet identity yet
 *       — [FIX-OIDC-USERS] is explicitly DEFERRED and the renderer uses the ADVISORY
 *       {@code src:["tag:hugmesh"]}. Per-operator src was precision the tailnet cannot enforce,
 *       naming principals headscale does not know. The load-bearing per-operator/per-key cut is
 *       Layer-B (the per-node sshd {@code AuthorizedKeysCommand}, which pins {@code %f}); Layer-A
 *       is REAL on the destination side and ADVISORY on the source side, and now says so.</li>
 * </ol>
 *
 * <h3>Pure + deterministic (so the push is IDEMPOTENT)</h3>
 * No IO; given the same export body it emits BYTE-IDENTICAL policy text (fingerprints sorted,
 * stable field order via Jackson {@link ObjectNode} insertion, fixed header). The reconcile loop
 * relies on that: it compiles, compares to the last-pushed text, and PUSHES ONLY ON CHANGE.
 *
 * <h3>Conservative, default-DENY shape</h3>
 * The export is ALREADY the default-deny compiled allow-set (no entry → no access). This
 * compiler invents exactly ONE rule the export did not carry — the SUPERADMIN mesh rule — and it
 * does so because the node renderer does (parity, not widening; the export CANNOT carry it, see
 * {@link AuthorizedOperator}'s POST-VERIFY CORRECTION note). Otherwise:
 * <ul>
 *   <li>only nodes named by {@code operators[]} get an {@code ssh} accept — never a wildcard;</li>
 *   <li>an EMPTY export compiles to the SUPERADMIN mesh rule alone plus the CIDR data-plane rule
 *       — exactly what the renderer emits for an empty export (see the gate's "EMPTY export
 *       still emits the SUPERADMIN mesh rule" scenario). Neither a wildcard nor a cleared
 *       policy, so pushing it neither widens nor blanks the mesh.</li>
 * </ul>
 * The {@code machine_key_fp} canonical-field caveat is inherited from the export (see
 * {@code docs/CANONICAL-FP.md}) — which is WHY the whole leg ships dark.
 */
public final class HeadscaleAclCompiler {

    /** headscale's tag namespace prefix — every tag name headscale parses is {@code tag:<name>}. */
    static final String TAG_PREFIX = "tag:";

    /**
     * The BARE, un-namespaced node-tag prefix, i.e. what the shell {@code dev_tag_for_fp} returns
     * in front of the hash. Kept distinct from {@link #TAG_PREFIX} because the shell twin yields
     * the un-namespaced form ({@code dev_<hash>}) and {@link #devTagFor(String)} must reproduce
     * that byte-for-byte, while the POLICY dst tag needs the {@code tag:} namespace on top.
     */
    static final String DEV_TAG_PREFIX = "dev_";

    /**
     * The host-tag prefix a node is addressed by in the compiled policy: {@code tag:dev_<hash>}.
     * MUST equal the prefix {@code hugmesh-headscale-forcetags} force-assigns and
     * {@code gen-headscale-policy.sh} renders as the ssh dst.
     *
     * <p>LOAD-BEARING: {@link #nodeTagFor(String)} builds EVERY emitted dst tag (ssh dst and
     * tagOwners key alike) out of this constant, so changing it changes the emitted policy.
     * Regression note — it used to be inert decoration: {@code nodeTagFor} independently
     * concatenated {@code TAG_PREFIX + devTagFor(fp)}, so this constant could be pointed back at
     * the dead {@code "tag:node-"} shape without altering one byte of the compiled document, and
     * the whole test suite stayed green. Never re-introduce a second, parallel way to spell it.
     */
    static final String NODE_TAG_PREFIX = TAG_PREFIX + DEV_TAG_PREFIX;

    /** The advisory SSH source tag (self-applied membership) — [FIX-OIDC-USERS] deferred. */
    static final String ADVISORY_SRC_TAG = "tag:hugmesh";

    /** The superadmin OPERATOR tag; control-owned + force-assigned, never self-applyable. */
    static final String SUPERADMIN_TAG = "tag:superadmin";

    /** The k8s pod CIDR of the data-plane rule the node policy KEEPS. */
    static final String POD_CIDR = "10.244.0.0/16";

    /** The k8s service/ClusterIP CIDR of the data-plane rule the node policy KEEPS. */
    static final String SERVICE_CIDR = "10.96.0.0/12";

    /** Static tagOwners head — mirrors {@code policy.hujson.tmpl}'s tagOwners block. */
    private static final List<String> STATIC_TAG_OWNERS =
            List.of("tag:hugmesh", "tag:pki", "tag:be", "tag:fe", "tag:host", SUPERADMIN_TAG);

    /** The control (headscale) user that owns every declared tag. */
    private static final String CONTROL_USER = "hugmesh";

    private final ObjectMapper mapper;

    /** The mesh whose membership tag the SUPERADMIN rule targets ({@code tag:mesh_<sanitised>}). */
    private final String meshId;

    /**
     * The node-local privileged unix account a tailnet-SSH session opens AS — the renderer's
     * {@code TS_SSH_USER} (node.env, staged from {@code resolve_ssh_user}; fallback "admin").
     */
    private final String sshUser;

    /** Back-compat constructor: mesh {@code mesh_default}, ssh user {@code admin}. */
    public HeadscaleAclCompiler(ObjectMapper mapper) {
        this(mapper, "mesh_default", "admin");
    }

    public HeadscaleAclCompiler(ObjectMapper mapper, String meshId, String sshUser) {
        this.mapper = mapper;
        this.meshId = (meshId == null || meshId.isBlank()) ? "mesh_default" : meshId;
        this.sshUser = (sshUser == null || sshUser.isBlank()) ? "admin" : sshUser;
    }

    /**
     * Compile {@code body} into the headscale ACL policy text (HuJSON: JSON plus a leading
     * {@code //} audit header, the SAME dialect {@code policy.hujson.tmpl} is written in and
     * headscale parses natively). Stable for a stable body. Never null; an empty/whitespace-only
     * export yields the renderer-equivalent minimum: the CIDR data-plane rule plus the SUPERADMIN
     * mesh rule.
     */
    public String compile(ExportBody body) {
        ObjectNode root = mapper.createObjectNode();

        long generation = body == null ? 0L : body.generation();
        String bodyMesh = (body == null || body.meshId() == null) ? "" : body.meshId();
        String meshTag = "tag:mesh_" + sanitiseTag(meshId);

        // ── tagOwners: the static head from policy.hujson.tmpl + one control-owned entry per
        // per-node dst tag [FIX-SERVERTAG]. Without these the dst tags are self-applyable and
        // the force-tagger's non-forgeability guarantee is void.
        ObjectNode tagOwners = mapper.createObjectNode();
        for (String t : STATIC_TAG_OWNERS) {
            ArrayNode owners = mapper.createArrayNode();
            owners.add(CONTROL_USER);
            tagOwners.set(t, owners);
        }

        // ── The distinct machine-key fingerprints the export licensed, sorted for determinism
        // (the renderer's `jq unique`). One node -> one dst tag -> one ssh edge, regardless of
        // how many operators or licenses reach it: the tailnet cannot tell operators apart yet
        // (see FICTIONAL SRC IDENTITY above), so per-operator duplication would be noise.
        Set<String> fingerprints = new TreeSet<>();
        List<AuthorizedOperator> operators = (body == null) ? List.of() : body.operators();
        if (operators != null) {
            for (AuthorizedOperator op : operators) {
                if (op == null) {
                    continue;
                }
                String operator = nz(op.operator());
                String fp = nz(op.machineKeyFp());
                if (operator.isEmpty() || fp.isEmpty()) {
                    // The export should never emit a blank operator/fp; skip defensively
                    // (fail-closed — a malformed entry must not become an unkeyed grant).
                    continue;
                }
                fingerprints.add(fp);
            }
        }

        for (String fp : fingerprints) {
            ArrayNode owners = mapper.createArrayNode();
            owners.add(CONTROL_USER);
            tagOwners.set(nodeTagFor(fp), owners);
        }

        // ── autoApprovers: the two advertised subnet routes the data-plane rule depends on.
        ObjectNode routes = mapper.createObjectNode();
        for (String cidr : List.of(POD_CIDR, SERVICE_CIDR)) {
            ArrayNode approvers = mapper.createArrayNode();
            approvers.add(ADVISORY_SRC_TAG);
            routes.set(cidr, approvers);
        }
        ObjectNode autoApprovers = mapper.createObjectNode();
        autoApprovers.set("routes", routes);

        // ── acls[]: the KEPT k8s pod/ClusterIP "one-LAN" data-plane rule [FIX-DROPMESHRULE].
        // NOT empty: an empty acls[] pushed in DB mode blanks cross-node pod/service
        // reachability fleet-wide. The any-to-any tag:hugmesh -> tag:hugmesh:* :22 hole stays
        // DROPPED — this rule's dst is CIDRs only, never a tag.
        ArrayNode acls = mapper.createArrayNode();
        ObjectNode dataPlane = mapper.createObjectNode();
        dataPlane.put("action", "accept");
        ArrayNode dpSrc = mapper.createArrayNode();
        dpSrc.add(ADVISORY_SRC_TAG);
        dataPlane.set("src", dpSrc);
        ArrayNode dpDst = mapper.createArrayNode();
        dpDst.add(POD_CIDR + ":*");
        dpDst.add(SERVICE_CIDR + ":*");
        dataPlane.set("dst", dpDst);
        acls.add(dataPlane);

        // ── ssh[]: headscale SSH is itself default-deny [FIX-DENY22], so these accepts ARE the
        // whole :22 surface. The SUPERADMIN mesh rule is FIRST and ALWAYS emitted (core nodes
        // the export omits are reachable ONLY this way); then one accept per licensed node.
        ArrayNode ssh = mapper.createArrayNode();
        ssh.add(sshRule(SUPERADMIN_TAG, meshTag));
        for (String fp : fingerprints) {
            ssh.add(sshRule(ADVISORY_SRC_TAG, nodeTagFor(fp)));
        }

        root.set("tagOwners", tagOwners);
        root.set("autoApprovers", autoApprovers);
        root.set("acls", acls);
        root.set("ssh", ssh);

        try {
            // Pretty + stable: Jackson preserves insertion order; the fingerprint set is sorted,
            // so the output is byte-identical for an identical body (the idempotency contract).
            // The leading // header is the audit marker (hujson = JSON + comments; the same
            // dialect policy.hujson.tmpl uses and headscale parses natively).
            return "// hugmesh device-license export -> headscale ACL; mesh=" + bodyMesh
                    + " generation=" + generation + " (compiled, do not hand-edit)\n"
                    + mapper.writerWithDefaultPrettyPrinter().writeValueAsString(root);
        } catch (JsonProcessingException e) {
            // Never expected for an ObjectNode tree; surface as a throw so the reconciler's
            // onErrorResume keeps last-good (fail-closed) rather than pushing a half-baked body.
            throw new IllegalStateException("headscale ACL compile failed", e);
        }
    }

    /** One {@code ssh} accept: {@code {action, src[1], dst[1], users[1]}} — the renderer's shape. */
    private ObjectNode sshRule(String src, String dst) {
        ObjectNode rule = mapper.createObjectNode();
        rule.put("action", "accept");
        ArrayNode s = mapper.createArrayNode();
        s.add(src);
        rule.set("src", s);
        ArrayNode d = mapper.createArrayNode();
        d.add(dst);
        rule.set("dst", d);
        // The node-local unix account the session opens AS (NOT the Casdoor operator). headscale
        // checks the tailnet identity; the per-node sshd (Layer-B) still independently re-derives
        // the role and pins the exact key fingerprints — this rule only opens the headscale edge.
        ArrayNode users = mapper.createArrayNode();
        users.add(sshUser);
        rule.set("users", users);
        return rule;
    }

    /**
     * The full headscale dst tag for a node: {@code tag:dev_<sha256(fp)[0:12]>} — exactly what
     * {@code hugmesh-headscale-forcetags} force-assigns and {@code gen-headscale-policy.sh}
     * renders as the ssh dst.
     */
    static String nodeTagFor(String machineKeyFp) {
        return NODE_TAG_PREFIX + hash12(machineKeyFp);
    }

    /**
     * The canonical machine-key-fingerprint → dst-tag mapping: {@link #DEV_TAG_PREFIX} plus the
     * first 12 lowercase hex characters of {@code sha256(fp)}. This is the UN-NAMESPACED shell
     * form; the policy dst tag adds headscale's {@code tag:} namespace — see
     * {@link #nodeTagFor(String)}, which builds it from {@link #NODE_TAG_PREFIX}.
     *
     * <p>BYTE-FOR-BYTE TWIN of the shell {@code dev_tag_for_fp} that exists in TWO places in
     * hugmesh-generator ({@code specs/usr/sbin/gen-headscale-policy.sh} and
     * {@code specs/usr/sbin/hugmesh-headscale-forcetags}):
     * <pre>{@code printf '%s' "$fp" | openssl dgst -sha256 | awk '{print $NF}' | cut -c1-12}</pre>
     * If the hash changes anywhere it must change in all three — a drift makes the forced tag
     * differ from the edge dst, i.e. the node becomes unreachable (fail-closed, never over-broad).
     */
    static String devTagFor(String machineKeyFp) {
        return DEV_TAG_PREFIX + hash12(machineKeyFp);
    }

    /**
     * {@code sha256(fp)} truncated to its first 12 lowercase hex characters — the shell's
     * {@code openssl dgst -sha256 | awk '{print $NF}' | cut -c1-12}. The ONE place the hash is
     * computed, so {@link #devTagFor(String)} and {@link #nodeTagFor(String)} cannot drift apart.
     */
    private static String hash12(String machineKeyFp) {
        byte[] digest;
        try {
            digest = MessageDigest.getInstance("SHA-256")
                    .digest(machineKeyFp.getBytes(StandardCharsets.UTF_8));
        } catch (NoSuchAlgorithmException e) {
            // SHA-256 is a mandated platform algorithm; unreachable.
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
        StringBuilder hex = new StringBuilder(12);
        for (int i = 0; i < 6; i++) {     // 6 bytes == 12 hex chars == `cut -c1-12`
            hex.append(Character.forDigit((digest[i] >> 4) & 0xF, 16));
            hex.append(Character.forDigit(digest[i] & 0xF, 16));
        }
        return hex.toString();
    }

    /**
     * headscale tag names allow {@code [a-z0-9-]}. Java twin of the shell {@code sanitise_tag}:
     * {@code tr '[:upper:]' '[:lower:]' | tr -c 'a-z0-9-' '-'} then collapse runs of {@code -}
     * and strip a leading/trailing {@code -}.
     */
    static String sanitiseTag(String s) {
        String lower = s.toLowerCase(Locale.ROOT);
        StringBuilder b = new StringBuilder(lower.length());
        for (int i = 0; i < lower.length(); i++) {
            char c = lower.charAt(i);
            b.append((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' ? c : '-');
        }
        String collapsed = b.toString().replaceAll("-{2,}", "-");
        if (collapsed.startsWith("-")) {
            collapsed = collapsed.substring(1);
        }
        if (collapsed.endsWith("-")) {
            collapsed = collapsed.substring(0, collapsed.length() - 1);
        }
        return collapsed;
    }

    private static String nz(String s) {
        return s == null ? "" : s;
    }
}
