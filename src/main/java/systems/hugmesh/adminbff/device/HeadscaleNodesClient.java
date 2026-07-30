package systems.hugmesh.adminbff.device;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import reactor.core.publisher.Flux;
import reactor.core.scheduler.Schedulers;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.concurrent.TimeUnit;

/**
 * Reads the set of headscale-enrolled nodes by shelling out to
 * {@code headscale nodes list -o json}. Headscale is the TRUST GATE of the machine_key_fp
 * AUTO-CAPTURE flow: it mints the machine keys, so it is the only authority for "what
 * fingerprint is genuinely enrolled in this mesh". The PENDING pick-list LEFT-JOINs this set
 * with {@code device_registry}; register RE-VALIDATES the offered fingerprint against it.
 *
 * <p>The blocking {@link Process} call is wrapped on {@link Schedulers#boundedElastic()} so
 * it never pins the Netty event loop. Every failure FAILS SOFT to an empty list (and the
 * caller decides: the pending list degrades to registry-only; register's re-validation honours
 * the break-glass {@code allow-manual-fp} flag) — headscale being down must never wedge the
 * admin console.
 *
 * <h3>⚠ CANONICAL FIELD UNCONFIRMED</h3>
 * Which JSON field carries the canonical fingerprint ({@code machineKey} vs {@code nodeKey})
 * is a CONFIG PARAMETER ({@link RegistryHeadscaleProperties#getFpField()}), NOT hard-coded,
 * precisely because it cannot be confirmed without a live control node. The default matches
 * what provision.sh bakes ({@code .Self.PublicKey} == {@code nodeKey}). Freeze the real choice
 * in {@code docs/CANONICAL-FP.md} on a live node before making register enforcing.
 */
public class HeadscaleNodesClient {

    private static final Logger log = LoggerFactory.getLogger(HeadscaleNodesClient.class);

    private final RegistryHeadscaleProperties props;
    private final ObjectMapper mapper;

    public HeadscaleNodesClient(RegistryHeadscaleProperties props, ObjectMapper mapper) {
        this.props = props;
        this.mapper = mapper;
    }

    /**
     * The currently-enrolled headscale nodes. Empty (never an error signal) when the feature
     * is disabled, the binary is missing/non-zero, the JSON is unparseable, or any node has no
     * fingerprint in the configured field — all fail-soft, so the caller fails closed/advisory
     * deliberately rather than the stream erroring.
     */
    public Flux<HeadscaleNode> listNodes() {
        if (!props.isEnabled()) {
            return Flux.empty();
        }
        return Flux.defer(() -> Flux.fromIterable(runAndParse()))
                .subscribeOn(Schedulers.boundedElastic());
    }

    private List<HeadscaleNode> runAndParse() {
        List<HeadscaleNode> out = new ArrayList<>();
        String json;
        try {
            ProcessBuilder pb = new ProcessBuilder(props.getBinary(), "nodes", "list", "-o", "json");
            pb.redirectErrorStream(false);
            Process p = pb.start();
            byte[] stdout = p.getInputStream().readAllBytes();
            boolean done = p.waitFor(props.getTimeoutMs(), TimeUnit.MILLISECONDS);
            if (!done) {
                p.destroyForcibly();
                log.warn("[headscale-nodes] '{} nodes list' timed out after {}ms — empty list (pending degrades to registry-only)",
                        props.getBinary(), props.getTimeoutMs());
                return out;
            }
            if (p.exitValue() != 0) {
                log.warn("[headscale-nodes] '{} nodes list' exited {} — empty list (pending degrades to registry-only)",
                        props.getBinary(), p.exitValue());
                return out;
            }
            json = new String(stdout, StandardCharsets.UTF_8);
        } catch (Exception e) {
            log.warn("[headscale-nodes] could not invoke headscale ({}): {} — empty list (pending degrades to registry-only)",
                    props.getBinary(), e.toString());
            return out;
        }
        return parse(json);
    }

    /**
     * Parse {@code headscale nodes list -o json} (a top-level array, or a {@code {"nodes":[…]}}
     * envelope depending on headscale version) into our reduced node records. Visible for
     * testing — the fingerprint extraction (which field, empty-guarding) is the load-bearing
     * bit and is unit-tested against synthetic JSON without a live binary.
     */
    List<HeadscaleNode> parse(String json) {
        List<HeadscaleNode> out = new ArrayList<>();
        try {
            JsonNode root = mapper.readTree(json);
            JsonNode arr = root.isArray() ? root
                    : root.has("nodes") ? root.get("nodes") : mapper.createArrayNode();
            for (JsonNode n : arr) {
                String fp = firstNonBlank(n, props.getFpField(), "machineKey", "nodeKey");
                if (fp == null) {
                    // No fingerprint in the configured field (or fallbacks) — skip; a node we
                    // cannot key is not a registrable candidate (fail-closed, never a blank fp).
                    continue;
                }
                String host = text(n, "givenName");
                if (host == null) host = text(n, "name");
                if (host == null) host = text(n, "hostname");
                String user = userOf(n);
                out.add(new HeadscaleNode(fp, host, user, meshOf(n, user)));
            }
        } catch (Exception e) {
            log.warn("[headscale-nodes] unparseable JSON from headscale — empty list: {}", e.toString());
            return new ArrayList<>();
        }
        return out;
    }

    /** First non-blank text value among the given field names (so {@code fp-field} wins, with
     *  the two known spellings as fallbacks). Null when none present/non-blank. */
    private static String firstNonBlank(JsonNode n, String... fields) {
        for (String f : fields) {
            String v = text(n, f);
            if (v != null) return v;
        }
        return null;
    }

    private static String text(JsonNode n, String field) {
        JsonNode v = n.get(field);
        if (v == null || v.isNull()) return null;
        String s = v.asText();
        return (s == null || s.isBlank()) ? null : s;
    }

    /** Headscale reports the user as either a string or a {@code {"name":…}} object across
     *  versions; normalise to the name string. */
    private static String userOf(JsonNode n) {
        JsonNode u = n.get("user");
        if (u == null || u.isNull()) return null;
        if (u.isTextual()) return text(n, "user");
        String name = text(u, "name");
        return name != null ? name : text(u, "displayName");
    }

    /** Best-effort mesh identifier: the node's first force/valid tag (e.g. {@code tag:mesh_x}),
     *  else the enrolling user. Advisory — the register re-validation only ENFORCES the
     *  meshId match when {@code allow-manual-fp=false}. */
    private static String meshOf(JsonNode n, String user) {
        for (String tagField : new String[]{"forcedTags", "validTags", "tags"}) {
            JsonNode tags = n.get(tagField);
            if (tags != null && tags.isArray() && !tags.isEmpty()) {
                Iterator<JsonNode> it = tags.elements();
                if (it.hasNext()) {
                    String t = it.next().asText();
                    if (t != null && !t.isBlank()) return t;
                }
            }
        }
        return user;
    }
}
