package net.hugmesh.adminbff.device;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
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
 * THIS compiler emits the headscale policy that carries one SSH edge per licensed node. Every
 * edge's source is {@code tag:superadmin} and nothing else (see SSH SOURCE below).
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
 *   <li><b>NO {@code tagOwners}.</b> [FIX-SERVERTAG] requires every security tag to be
 *       DECLARED with an EMPTY owner list, so no node can self-advertise it and only the
 *       force-tagger can assign it. A policy without {@code tagOwners} re-opens the masquerade
 *       hole the force-tagger closed. (Corrected again 2026-11-11: the first fix declared the
 *       security tags OWNED by the membership user, the shape hugmesh-generator #888/#896
 *       removed from the live writer. Every pre-auth key is minted for that user, so an owner
 *       there let a node self-assign the tag. See {@link #MEMBERSHIP_OWNER}.)</li>
 *   <li><b>FICTIONAL SRC IDENTITY.</b> It emitted {@code src:["group:op-<operator>"]} with the
 *       Casdoor subject as the group member. headscale has NO per-operator tailnet identity yet
 *       — [FIX-OIDC-USERS] is explicitly DEFERRED — so per-operator src was precision the
 *       tailnet cannot enforce, naming principals headscale does not know. (Corrected again
 *       2026-11-11: the first fix sourced each per-node edge from the membership tag
 *       {@code tag:hugmesh}, as the renderer then did. See SSH SOURCE below.)</li>
 * </ol>
 *
 * <h3>SSH SOURCE: {@code tag:superadmin} only (2026-11-11, hugmesh-generator #1018)</h3>
 * Every {@code ssh} rule this compiler emits names {@link #SUPERADMIN_TAG} as its only source,
 * the mesh rule and every per-node edge alike. Until 2026-11-11 the per-node edges were sourced
 * from {@code tag:hugmesh} and described as "advisory", on the assumption that the per-node sshd
 * (Layer-B) still checked the operator's key. It does not on this path: Tailscale SSH
 * ({@code tailscale up --ssh}, on by default) answers {@code :22} itself, so whoever an
 * {@code ssh} rule names as source gets a session as the privileged user and nothing else
 * stands in the way. {@code tag:hugmesh} is self-applied by every node that holds a pre-auth
 * key, so that source was every member. {@code tag:superadmin} has no owner and only the
 * force-tagger assigns it, from the control node's superadmin machine list.
 *
 * <p>Consequences, all mirrored from the renderer:
 * <ul>
 *   <li>a licensed operator who is only a member gets NO Tailscale SSH session until
 *       per-operator identities land; the per-node edges keep the export-driven shape an
 *       operator source will later slot into, and until then open nothing the mesh rule does
 *       not;</li>
 *   <li>{@code acls[]} carries one {@code :22} accept, {@code tag:superadmin ->
 *       tag:hugmesh:22}. A Tailscale SSH session is a TCP connection to {@code :22}, so the
 *       packet filter must pass it before the {@code ssh} block is consulted; without the accept
 *       the superadmin rule was unreachable. Its source is {@code tag:superadmin} only. Which
 *       node accepts a SESSION is still decided by the {@code ssh} rule's destination.</li>
 * </ul>
 *
 * <h3>Pure + deterministic (so the push is IDEMPOTENT)</h3>
 * No IO; given the same export body it emits BYTE-IDENTICAL policy text (fingerprints sorted,
 * stable field order via Jackson {@link ObjectNode} insertion, fixed header). The reconcile loop
 * relies on that: it compiles, compares to the last-pushed text, and PUSHES ONLY ON CHANGE.
 *
 * <h3>Conservative, default-DENY shape</h3>
 * The export is ALREADY the default-deny compiled allow-set (no entry → no access). This
 * compiler adds exactly TWO rules the export did not carry — the SUPERADMIN mesh rule and the
 * superadmin-only {@code :22} accept that makes it reachable — and it does so because the node
 * renderer does (parity, not widening; the export CANNOT carry them, see
 * {@link AuthorizedOperator}'s POST-VERIFY CORRECTION note). Otherwise:
 * <ul>
 *   <li>only nodes named by {@code operators[]} get a per-node {@code ssh} accept — never a
 *       wildcard, and never a member source;</li>
 *   <li>an EMPTY export compiles to the SUPERADMIN mesh rule alone plus the two {@code acls}
 *       rules (the CIDR data-plane rule and the superadmin {@code :22} accept) — exactly what
 *       the renderer emits for an empty export (see the gate's "EMPTY export still emits the
 *       SUPERADMIN mesh rule" scenario). Neither a wildcard nor a cleared policy, so pushing it
 *       neither widens nor blanks the mesh.</li>
 * </ul>
 * The {@code machine_key_fp} canonical-field caveat is inherited from the export (see
 * {@code docs/CANONICAL-FP.md}) — which is WHY the whole leg ships dark.
 */
@SuppressFBWarnings(value = "EI_EXPOSE_REP2",
        justification = "Spring constructor injection: the container owns this singleton collaborator and it is never mutated by this class after construction; a defensive copy of a bean is meaningless (not caller-owned mutable data).")
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

    /**
     * The self-applied MEMBERSHIP tag: every node holding a pre-auth key advertises it. It is
     * the source of the data-plane rule, the route auto-approver and the destination of the one
     * {@code :22} accept. It is NEVER an {@code ssh} or {@code :22} SOURCE: Tailscale SSH has no
     * other gate, so a member source is a privileged session for every member.
     */
    static final String MEMBERSHIP_TAG = "tag:hugmesh";

    /**
     * The superadmin OPERATOR tag; owned by NO user (empty owner list) + force-assigned. The
     * ONLY source any emitted {@code ssh} rule names, and the only source of the {@code :22}
     * accept (the renderer's {@code SSH_SRC}).
     */
    static final String SUPERADMIN_TAG = "tag:superadmin";

    /**
     * The destination of the one {@code :22} accept: the membership tag, port 22. The renderer's
     * template spells it statically as {@code tag:hugmesh:22} (not {@code tag:mesh_<id>:22}), so
     * a node must validly hold {@link #MEMBERSHIP_TAG} for the superadmin to reach its
     * {@code :22}.
     */
    static final String SSH_PORT_DST = MEMBERSHIP_TAG + ":22";

    /** The k8s pod CIDR of the data-plane rule the node policy KEEPS. */
    static final String POD_CIDR = "10.244.0.0/16";

    /** The k8s service/ClusterIP CIDR of the data-plane rule the node policy KEEPS. */
    static final String SERVICE_CIDR = "10.96.0.0/12";

    /**
     * The MEMBERSHIP tags of the static tagOwners head — mirrors {@code policy.hujson.tmpl}.
     * Every node self-applies these with {@code --advertise-tags} (data-plane membership: the
     * CIDR rule and route auto-approval), so they stay owned by {@link #MEMBERSHIP_OWNER}.
     * None of them is an ssh src or dst; {@code tag:hugmesh} is the {@code :22} accept's
     * destination and never a source of it.
     */
    private static final List<String> MEMBERSHIP_TAGS =
            List.of("tag:hugmesh", "tag:pki", "tag:be", "tag:fe", "tag:host");

    /**
     * The headscale user every pre-auth key is minted for (and so the user every node registers
     * as). It owns the {@link #MEMBERSHIP_TAGS} and NOTHING ELSE.
     *
     * <p>[FIX-SERVERTAG] The SECURITY tags — {@link #SUPERADMIN_TAG}, this mesh's
     * {@code tag:mesh_<id>} and every per-node {@code tag:dev_<fp>} — are declared with the
     * EMPTY owner list. headscale 0.23 (the pinned version) gives a node its forced tags PLUS
     * every advertised tag whose owner list names the node's own user; a forced tag does not
     * cancel a different advertised one. So an owner here would let any holder of any pre-auth
     * key self-assign the tag. With no owner an advertised security tag is always invalid, while
     * {@code headscale nodes tag} (hugmesh-generator {@code hugmesh-headscale-forcetags}) does not
     * consult tagOwners and still assigns it. This is the node-side writer's rule since
     * hugmesh-generator #896, held to it by the shared parity golden.
     */
    private static final String MEMBERSHIP_OWNER = "hugmesh";

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
     * export yields the renderer-equivalent minimum: the CIDR data-plane rule, the superadmin-only
     * {@code :22} accept and the SUPERADMIN mesh rule.
     */
    public String compile(ExportBody body) {
        ObjectNode root = mapper.createObjectNode();

        long generation = body == null ? 0L : body.generation();
        String bodyMesh = (body == null || body.meshId() == null) ? "" : body.meshId();
        String meshTag = "tag:mesh_" + sanitiseTag(meshId);

        // ── tagOwners [FIX-SERVERTAG]: two classes that must never share an owner.
        //   * membership tags (the template's static head) are owned by MEMBERSHIP_OWNER;
        //   * SECURITY tags (tag:superadmin, tag:mesh_<id>, every tag:dev_<fp>) are declared
        //     with the EMPTY owner list: nobody may self-advertise them, the force-tagger
        //     assigns them. See MEMBERSHIP_OWNER for why an owner here is the hole.
        // tag:mesh_<id> must be DECLARED although nothing advertises it: headscale 0.23 fails
        // every node's map update while a rule names a tag that has neither a tagOwners entry
        // nor a node already forced to carry it (the renderer declares it for the same reason).
        ObjectNode tagOwners = mapper.createObjectNode();
        for (String t : MEMBERSHIP_TAGS) {
            ArrayNode owners = mapper.createArrayNode();
            owners.add(MEMBERSHIP_OWNER);
            tagOwners.set(t, owners);
        }
        tagOwners.set(SUPERADMIN_TAG, mapper.createArrayNode());
        tagOwners.set(meshTag, mapper.createArrayNode());

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
            tagOwners.set(nodeTagFor(fp), mapper.createArrayNode());   // security tag: no owner
        }

        // ── autoApprovers: the two advertised subnet routes the data-plane rule depends on.
        ObjectNode routes = mapper.createObjectNode();
        for (String cidr : List.of(POD_CIDR, SERVICE_CIDR)) {
            ArrayNode approvers = mapper.createArrayNode();
            approvers.add(MEMBERSHIP_TAG);
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
        dpSrc.add(MEMBERSHIP_TAG);
        dataPlane.set("src", dpSrc);
        ArrayNode dpDst = mapper.createArrayNode();
        dpDst.add(POD_CIDR + ":*");
        dpDst.add(SERVICE_CIDR + ":*");
        dataPlane.set("dst", dpDst);
        acls.add(dataPlane);

        // The ONLY way to :22. A Tailscale SSH session is a TCP connection to :22, so the packet
        // filter must pass it before ssh[] is consulted; without this accept the superadmin rule
        // below is unreachable. src is tag:superadmin and nothing else: a member src here would
        // open :22 to every pre-auth key holder. dst is the membership tag on port 22 only.
        ObjectNode sshPort = mapper.createObjectNode();
        sshPort.put("action", "accept");
        ArrayNode spSrc = mapper.createArrayNode();
        spSrc.add(SUPERADMIN_TAG);
        sshPort.set("src", spSrc);
        ArrayNode spDst = mapper.createArrayNode();
        spDst.add(SSH_PORT_DST);
        sshPort.set("dst", spDst);
        acls.add(sshPort);

        // ── ssh[]: headscale SSH is itself default-deny [FIX-DENY22], so these accepts ARE the
        // whole SSH surface. The SUPERADMIN mesh rule is FIRST and ALWAYS emitted (core nodes
        // the export omits are reachable ONLY this way); then one accept per licensed node.
        // EVERY rule's src is tag:superadmin (see SSH SOURCE in the class comment): there is no
        // per-operator tailnet identity to name, and the membership tag is every member. So a
        // per-node edge opens nothing the mesh rule does not, until an operator source exists.
        ArrayNode ssh = mapper.createArrayNode();
        ssh.add(sshRule(SUPERADMIN_TAG, meshTag));
        for (String fp : fingerprints) {
            ssh.add(sshRule(SUPERADMIN_TAG, nodeTagFor(fp)));
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
        // checks the tailnet identity (src) and NOTHING else does: Tailscale SSH answers :22
        // itself, so the per-node sshd (Layer-B) and its key pinning are not on this path.
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
