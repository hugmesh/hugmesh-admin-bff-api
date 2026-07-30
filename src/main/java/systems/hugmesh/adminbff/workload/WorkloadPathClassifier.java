package systems.hugmesh.adminbff.workload;

import org.springframework.http.HttpMethod;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Maps a WORKLOAD CONSOLE request path+method to its {@link DangerTier} and extracts the
 * target namespace (for the STEP-0b allowlist check) — WITHOUT consulting the HTTP verb for
 * the tier decision (DESIGN AXIOM: tier is keyed on the capability, never the method). The
 * filter uses this to know which tier to authorize and which namespace to gate.
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

    /** {ns} appears as the segment after .../pods/{ns}/... in both surfaces. */
    private static final Pattern NS_AFTER_PODS =
            Pattern.compile("/pods/([^/]+)(?:/|$)");
    /** lifecycle/exec/port-forward also address {ns} as .../{ns}/{kind-or-workload}/... */
    private static final Pattern NS_AFTER_LIFECYCLE =
            Pattern.compile("/(?:lifecycle|exec|port-forward|network|storage|events|metrics)/([^/]+)(?:/|$)");

    /** True iff the path is a workload-console path (either surface). */
    public static boolean isConsolePath(String path) {
        return path != null && (path.startsWith(ADMIN_PREFIX) || path.startsWith(SUPERADMIN_PREFIX));
    }

    public static boolean isAdminSurface(String path) {
        return path != null && path.startsWith(ADMIN_PREFIX);
    }

    public static boolean isSuperadminSurface(String path) {
        return path != null && path.startsWith(SUPERADMIN_PREFIX);
    }

    /** True iff this path requests a log BODY (gated on the grant's log_access). */
    public static boolean isLogPath(String path) {
        return path != null && path.contains("/logs");
    }

    /**
     * The danger TIER for a path+method. Grants/config CRUD + the capability probe are READ
     * (the predicate still gates them SA-only via the surface). The exact danger paths:
     * <ul>
     *   <li>DANGEROUS — /logs/stream, /exec, /port-forward, /lifecycle (any GitOps verb).</li>
     *   <li>RUNTIME_MUTATE — /rollout-restart, DELETE on /pods/.</li>
     *   <li>READ — everything else.</li>
     * </ul>
     */
    public static DangerTier tierOf(String path, HttpMethod method) {
        if (path == null) return DangerTier.READ;
        if (path.contains("/logs/stream")
                || path.contains("/exec")
                || path.contains("/port-forward")
                || path.contains("/lifecycle")) {
            return DangerTier.DANGEROUS;
        }
        if (path.contains("/rollout-restart")) {
            return DangerTier.RUNTIME_MUTATE;
        }
        if (HttpMethod.DELETE.equals(method) && path.contains("/pods/")) {
            return DangerTier.RUNTIME_MUTATE;
        }
        return DangerTier.READ;
    }

    /**
     * Extract the target namespace from the path for the STEP-0b allowlist check, or null if
     * the path is not namespace-addressed (e.g. the capability probe, grants/config CRUD,
     * the cluster-wide pod list). A null namespace means "no {ns} to gate" — the filter treats
     * it as allowed at STEP 0b (the read SA's cluster-read RBAC + the per-namespace projection
     * are the in-cluster backstop for the all-namespaces list).
     */
    public static String namespaceOf(String path) {
        if (path == null) return null;
        Matcher m = NS_AFTER_PODS.matcher(path);
        if (m.find()) return decode(m.group(1));
        m = NS_AFTER_LIFECYCLE.matcher(path);
        if (m.find()) return decode(m.group(1));
        return null;
    }

    private static String decode(String s) {
        try {
            return java.net.URLDecoder.decode(s, java.nio.charset.StandardCharsets.UTF_8);
        } catch (Exception e) {
            return s;
        }
    }
}
