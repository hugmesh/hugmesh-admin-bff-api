package net.hugmesh.adminbff.workload;

import org.springframework.http.HttpMethod;
import org.springframework.http.server.PathContainer;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/**
 * Maps a WORKLOAD CONSOLE request path+method to its {@link DangerTier} and extracts the
 * target namespace (for the STEP-0b allowlist check) — WITHOUT consulting the HTTP verb for
 * the tier decision (DESIGN AXIOM: tier is keyed on the capability, never the method). The
 * filter uses this to know which tier to authorize and which namespace to gate.
 *
 * <h3>Path form: classify what the ROUTER sees</h3>
 * Every method here takes the request path as the list of path SEGMENTS produced by
 * {@link #segmentsOf(PathContainer)}: percent-decoded once and with {@code ;matrix=params}
 * stripped, which is exactly the value Spring's {@code PathPattern} matching uses for the
 * {@code @RequestMapping}s, the {@code pathMatchers(...)} role rules and the WebSocket
 * handler mapping. The raw {@code getPath().value()} string must NEVER be classified: the
 * raw form of {@code /bff/admin/%77orkloads/...} does not start with {@code /bff/admin/workloads}
 * yet the router decodes it to the very same controller, so a raw-string classifier is a
 * bypass of the whole gate.
 *
 * <h3>Path families</h3>
 * <pre>
 *   /bff/admin/workloads/**       — admin READ surface (READ tier always; logs marked logPath)
 *   /bff/superadmin/workloads/**  — superadmin surface (tier per sub-path)
 * </pre>
 */
public final class WorkloadPathClassifier {

    private WorkloadPathClassifier() {
    }

    public static final String ADMIN_PREFIX = "/bff/admin/workloads";
    public static final String SUPERADMIN_PREFIX = "/bff/superadmin/workloads";

    /**
     * The first segment after the surface prefix that addresses a namespace, and so carries
     * {@code {ns}} as the very next segment (pods/{ns}/..., lifecycle/{ns}/..., exec/{ns}/...,
     * and the exec-tty WebSocket handshake exec-tty/{ns}/{pod}).
     */
    private static final Set<String> NAMESPACE_FAMILIES = Set.of(
            "pods", "lifecycle", "exec", "exec-tty", "port-forward",
            "network", "storage", "events", "metrics");

    /**
     * The request path as the router sees it: one entry per path segment, percent-decoded once
     * with path parameters ({@code ;x=1}) removed. Separators and empty segments are dropped
     * (so {@code //} cannot hide a segment); a segment that is empty only after its parameters
     * were stripped is kept as {@code ""} so positions stay aligned with the router's.
     */
    public static List<String> segmentsOf(PathContainer path) {
        List<String> out = new ArrayList<>();
        if (path == null) return out;
        for (PathContainer.Element e : path.elements()) {
            if (e instanceof PathContainer.PathSegment seg && !seg.value().isEmpty()) {
                out.add(seg.valueToMatch());
            }
        }
        return out;
    }

    /** The segments after {@code /bff/{admin,superadmin}/workloads}, or null if not a console path. */
    private static List<String> afterPrefix(List<String> segs) {
        if (segs == null || segs.size() < 3) return null;
        if (!"bff".equalsIgnoreCase(segs.get(0))) return null;
        String surface = segs.get(1);
        if (!"admin".equalsIgnoreCase(surface) && !"superadmin".equalsIgnoreCase(surface)) return null;
        // startsWith, not equals: keeps the legacy over-match (a console-looking prefix is gated).
        if (!segs.get(2).toLowerCase(Locale.ROOT).startsWith("workloads")) return null;
        return segs.subList(3, segs.size());
    }

    /** The path with "." and ".." segments resolved (a ".." never climbs above the root). */
    private static List<String> resolveDots(List<String> segs) {
        List<String> out = new ArrayList<>();
        for (String s : segs) {
            if (".".equals(s)) continue;
            if ("..".equals(s)) {
                if (!out.isEmpty()) out.remove(out.size() - 1);
                continue;
            }
            out.add(s);
        }
        return out;
    }

    /**
     * True iff the path is a workload-console path (either surface). FAIL-CLOSED on dot
     * segments: it is a console path if EITHER its literal segments OR its dot-resolved form
     * (what a normalising proxy in front would forward) are under the console prefix.
     */
    public static boolean isConsolePath(List<String> segs) {
        return afterPrefix(segs) != null || afterPrefix(resolveDots(segs)) != null;
    }

    public static boolean isAdminSurface(List<String> segs) {
        return isConsolePath(segs) && isSurface(segs, "admin");
    }

    public static boolean isSuperadminSurface(List<String> segs) {
        return isConsolePath(segs) && isSurface(segs, "superadmin");
    }

    private static boolean isSurface(List<String> segs, String surface) {
        return (afterPrefix(segs) != null && surface.equalsIgnoreCase(segs.get(1)))
                || (afterPrefix(resolveDots(segs)) != null && surface.equalsIgnoreCase(resolveDots(segs).get(1)));
    }

    /**
     * True iff any segment is "." or "..". The router matches these literally (it never
     * resolves them), so a console request carrying one is ambiguous between the router and
     * any normalising hop: the filter refuses it outright rather than guess.
     */
    public static boolean hasDotSegment(List<String> segs) {
        for (String s : segs) {
            if (".".equals(s) || "..".equals(s)) return true;
        }
        return false;
    }

    /** The decoded segments joined as {@code /a/b/c} — the form the tier/log checks scan. */
    private static String joined(List<String> segs) {
        StringBuilder sb = new StringBuilder();
        for (String s : segs) sb.append('/').append(s.toLowerCase(Locale.ROOT));
        return sb.toString();
    }

    /** True iff this path requests a log BODY (gated on the grant's log_access). */
    public static boolean isLogPath(List<String> segs) {
        return segs != null && joined(segs).contains("/logs");
    }

    /**
     * The danger TIER for a path+method. Grants/config CRUD + the capability probe are READ
     * (the predicate still gates them SA-only via the surface). The exact danger paths:
     * <ul>
     *   <li>DANGEROUS — /logs/stream, /exec, /port-forward, /lifecycle (any GitOps verb).</li>
     *   <li>RUNTIME_MUTATE — /rollout-restart, DELETE on /pods/.</li>
     *   <li>READ — everything else.</li>
     * </ul>
     * The scan is deliberately a substring scan over the decoded, case-folded path: it can
     * only over-classify (a pod literally named "exec" is DANGEROUS), never under-classify.
     */
    public static DangerTier tierOf(List<String> segs, HttpMethod method) {
        if (segs == null) return DangerTier.READ;
        String p = joined(segs);
        if (p.contains("/logs/stream")
                || p.contains("/exec")
                || p.contains("/port-forward")
                || p.contains("/lifecycle")) {
            return DangerTier.DANGEROUS;
        }
        if (p.contains("/rollout-restart")) {
            return DangerTier.RUNTIME_MUTATE;
        }
        if (HttpMethod.DELETE.equals(method) && p.contains("/pods/")) {
            return DangerTier.RUNTIME_MUTATE;
        }
        return DangerTier.READ;
    }

    /**
     * Extract the target namespace for the STEP-0b allowlist check, or null if the path is not
     * namespace-addressed (e.g. the capability probe, grants/config CRUD, the cluster-wide pod
     * list). A null namespace means "no {ns} to gate" — the filter treats it as allowed at
     * STEP 0b (the read SA's cluster-read RBAC + the per-namespace projection are the
     * in-cluster backstop for the all-namespaces list).
     *
     * <p>POSITIONAL, like the router: the family keyword is the FIRST segment after the
     * prefix and {@code {ns}} the segment right after it. (Searching for the keyword anywhere
     * let {@code /lifecycle/ns1/pods/ns2/x} be gated as {@code ns2} while the controller acted
     * on {@code ns1}.) The segment is already decoded once, as the controller sees it; it is
     * not decoded again.
     */
    public static String namespaceOf(List<String> segs) {
        List<String> rest = afterPrefix(segs);
        if (rest == null) rest = afterPrefix(resolveDots(segs));
        if (rest == null || rest.size() < 2) return null;
        if (!NAMESPACE_FAMILIES.contains(rest.get(0).toLowerCase(Locale.ROOT))) return null;
        return rest.get(1);
    }
}
