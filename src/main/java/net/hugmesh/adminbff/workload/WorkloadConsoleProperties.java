package net.hugmesh.adminbff.workload;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * Static, server-side WORKLOAD CONSOLE configuration — the generator-curated allowlists and
 * the feature gate. These are NOT runtime/DB toggles (those live in
 * {@code workload_console_config}); they are build-time, GitOps-owned facts the generator
 * emits ONLY when {@code workloadConsole.enabled=true}. With the feature gated off the BFF
 * leaves {@link #enabled} false (the DEFAULT) and every console controller is unreachable
 * (the {@link WorkloadAuthorizationFilter} denies the whole prefix) — three independent OFFs
 * (this gate, the DB master flag, an active grant).
 *
 * <h3>The two authoritative allowlists (DESIGN AXIOM 3)</h3>
 * <ul>
 *   <li>{@link #namespaceAllowlist} — the APP-TIER namespaces the console may EVER touch.
 *       Checked BEFORE any k8s call (STEP 0b). It EXCLUDES every infra tier
 *       (hugmesh-pki / devops / observability) so a cross-TIER reach is impossible. An
 *       out-of-allowlist namespace is a 403 + probe audit, never a k8s call.</li>
 *   <li>{@link #portForwardAllowlist} — the curated {@code (namespace, workload, port)}
 *       triples a superadmin may port-forward to (DECISION 2), EXCLUDING every
 *       datastore/Vault/PKI/Casdoor.</li>
 * </ul>
 * {@link #execReadOnlyCommands} is the read-only exec command allowlist (the safe
 * non-TTY exec variant); the full interactive TTY is gated by the danger tier + step-up +
 * Lease + device/SSH-license, not by this list. A one-token entry is a BARE NAME
 * (any arguments); a multi-token entry is a PINNED ARGV matched against the WHOLE
 * requested argv — see {@link #execReadOnlyAllowed}.
 */
@ConfigurationProperties(prefix = "app.workload-console")
public class WorkloadConsoleProperties {

    /** The generator gate. DEFAULT false — the whole feature is dark unless the generator
     *  emitted it (and even then the DB master flag + an active grant gate access). */
    private boolean enabled = false;

    /** APP-TIER namespaces the console may touch. EMPTY by default (fail-closed: with no
     *  allowlist every {ns} is out-of-allowlist -> 403). */
    private List<String> namespaceAllowlist = new ArrayList<>();

    /** Curated (namespace, workload, port) port-forward triples (DECISION 2). */
    private List<PortForwardTarget> portForwardAllowlist = new ArrayList<>();

    /** The read-only exec command allowlist, in the generator's two forms: a BARE NAME
     *  ({@code "ls"}) licenses that command with any arguments; a PINNED ARGV, its tokens
     *  joined by single spaces ({@code "ps -e"} is {@code [ps, -e]}), licenses exactly that
     *  whole argv (see {@link #execReadOnlyAllowed}). EMPTY by default (fail-closed:
     *  nothing is exec-able). */
    private List<String> execReadOnlyCommands = new ArrayList<>();

    /** Default grant TTL in hours (DECISION 4/6, ~24h). */
    private long grantTtlHours = 24;

    /** The k8s seam's two projected SA token files (read / mutate). */
    private K8s k8s = new K8s();

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public List<String> getNamespaceAllowlist() {
        return namespaceAllowlist;
    }

    public void setNamespaceAllowlist(List<String> namespaceAllowlist) {
        this.namespaceAllowlist = namespaceAllowlist == null ? new ArrayList<>() : namespaceAllowlist;
    }

    public List<PortForwardTarget> getPortForwardAllowlist() {
        return portForwardAllowlist;
    }

    public void setPortForwardAllowlist(List<PortForwardTarget> portForwardAllowlist) {
        this.portForwardAllowlist = portForwardAllowlist == null ? new ArrayList<>() : portForwardAllowlist;
    }

    public List<String> getExecReadOnlyCommands() {
        return execReadOnlyCommands;
    }

    public void setExecReadOnlyCommands(List<String> execReadOnlyCommands) {
        this.execReadOnlyCommands = execReadOnlyCommands == null ? new ArrayList<>() : execReadOnlyCommands;
    }

    public long getGrantTtlHours() {
        return grantTtlHours;
    }

    public void setGrantTtlHours(long grantTtlHours) {
        this.grantTtlHours = grantTtlHours;
    }

    public K8s getK8s() {
        return k8s;
    }

    public void setK8s(K8s k8s) {
        this.k8s = k8s == null ? new K8s() : k8s;
    }

    // ── derived helpers ─────────────────────────────────────────────────────────

    /** The namespace allowlist as a Set for O(1) STEP-0b membership checks. */
    public Set<String> namespaceAllowSet() {
        return new LinkedHashSet<>(namespaceAllowlist);
    }

    /** True iff {@code ns} is in the APP-TIER allowlist (fail-closed: empty allowlist
     *  rejects everything). A null/blank ns is always rejected. */
    public boolean namespaceAllowed(String ns) {
        return ns != null && !ns.isBlank() && namespaceAllowlist.contains(ns);
    }

    /** True iff the (namespace, workload, port) triple is a curated port-forward target. */
    public boolean portForwardAllowed(String ns, String workload, int port) {
        for (PortForwardTarget t : portForwardAllowlist) {
            if (t.matches(ns, workload, port)) return true;
        }
        return false;
    }

    /**
     * True iff {@code command} is licensed by one allowlist entry, under the generator's TWO
     * deliberate entry forms (hugmesh-generator
     * {@code specs/cluster/manifests/admin-bff-api/workload-console-patch.yaml}, env
     * {@code WORKLOAD_CONSOLE_EXEC_READONLY}: "BARE NAME ONLY for a command that holds the
     * property under ARBITRARY argv. PINNED ARGV an exact, whole-argv safe form"):
     * <ul>
     *   <li><b>BARE NAME</b> — a ONE-token entry ({@code "ls"}, {@code "uname"}) licenses
     *       its command with ARBITRARY arguments: the head token must equal the entry, the
     *       rest is free. The generator admits a bare name only after auditing that command
     *       under arbitrary argv (its {@code tests/workload-console/exec_argv_property.py}
     *       re-derives that on every run), so {@code [ls, -la, /]} is licensed by
     *       {@code "ls"} — narrowing it here would silently drop a capability the curation
     *       deliberately kept;</li>
     *   <li><b>PINNED ARGV</b> — a MULTI-token entry ({@code "ps -e"}, {@code "df -h"},
     *       {@code "stat -t"}, {@code "date -u"}) licenses EXACTLY that argv: same length,
     *       same tokens, same order, case-sensitive. No prefix match ({@code "ps -e"} does
     *       not license {@code [ps, -e, eww]}), and no head match ({@code [ps]} or
     *       {@code [ps, eww]} is refused when only {@code "ps -e"} is listed). Pinning is how
     *       the generator lists a command whose bare form is NOT argument-safe
     *       ({@code ps eww} prints every process's environment, {@code date -f FILE} echoes
     *       FILE's lines, {@code df --output=… <path>} is a mount-topology oracle).</li>
     * </ul>
     *
     * <p><b>Why not the first token alone.</b> This used to be
     * {@code execReadOnlyCommands.contains(command.get(0))}. That honoured the BARE form but
     * made every PINNED form unreachable: the real argv {@code [ps, -e]} has the head
     * {@code ps}, which is not an entry, and the only argv whose head equalled
     * {@code "ps -e"} was the one-token {@code [ps -e]} — a program literally named
     * "ps -e", not {@code ps}. (The generator's cross-repo TODO asked for exactly this fix:
     * "match the WHOLE argv … not command.get(0)".)
     *
     * <p>No shell semantics and no normalisation on the {@code command} side: nothing is
     * unquoted, split, globbed, trimmed, case-folded or path-resolved. So {@code [ps -e]}
     * (ONE token containing a space), {@code [/bin/ps, -e]}, {@code [ps, -e;env]},
     * {@code [ls;env]} and {@code [sh, -c, ps -e]} are refused. A bare name's free
     * arguments are passed on as argv elements ({@code Fabric8WorkloadClient} hands the
     * list over as a {@code String[]}, never to a shell), so a metacharacter there is just a
     * file-name argument to the audited command. A MALFORMED entry licenses nothing (see
     * {@link #entryArgv}); a null/empty command, or one whose head is null, is refused; the
     * default (empty) allowlist refuses everything.
     */
    public boolean execReadOnlyAllowed(List<String> command) {
        if (command == null || command.isEmpty()) return false;
        for (String entry : execReadOnlyCommands) {
            List<String> argv = entryArgv(entry);
            if (argv == null) continue;
            if (argv.size() == 1) {
                // BARE NAME: head must match; the remaining arguments are free.
                if (argv.get(0).equals(command.get(0))) return true;
            } else if (argv.equals(command)) {
                // PINNED ARGV: List.equals is element-wise, length- and order-sensitive, and
                // calls equals() on argv's (never-null) elements, so a null token in command
                // is simply unequal rather than an NPE.
                return true;
            }
        }
        return false;
    }

    /**
     * One allowlist entry as the exact argv it licenses, or {@code null} when the entry is
     * MALFORMED and must license nothing.
     *
     * <p>The split is on the single ASCII space {@code ' '} and nothing else, because that is
     * how the generator writes a pinned form (its argv "space-joined, flags only, no path").
     * An entry is malformed when it is null/empty, when splitting it yields an EMPTY token (a
     * leading, trailing or doubled space), or when a token contains any other whitespace,
     * Unicode space or ISO control character. Refusing those instead of "cleaning them up" is
     * the point: a mistyped {@code "ps  -e"} would otherwise license an argv carrying an
     * empty-string argument, and a tab, newline or no-break space inside an entry has no
     * reading that is both exact and obviously intended. (Spring's comma-delimited binding of
     * {@code WORKLOAD_CONSOLE_EXEC_READONLY} already trims each element — pinned by
     * {@code WorkloadConsolePropertiesTest} — so blanks around a comma never reach here; and
     * that same comma split is why no entry can itself contain a comma.)
     */
    static List<String> entryArgv(String entry) {
        if (entry == null || entry.isEmpty()) return null;
        String[] tokens = entry.split(" ", -1);
        for (String t : tokens) {
            if (t.isEmpty()) return null;
            for (int i = 0; i < t.length(); i++) {
                char c = t.charAt(i);
                if (Character.isWhitespace(c) || Character.isSpaceChar(c)
                        || Character.isISOControl(c)) {
                    return null;
                }
            }
        }
        return List.of(tokens);
    }

    /**
     * The k8s seam ({@code app.workload-console.k8s.*}) — the two PROJECTED ServiceAccount
     * token files the deployment mounts ({@code automountServiceAccountToken:false} on both
     * SAs; the generator's workload-console-rbac provisions them). Each file is the SOLE
     * credential of its half: an absent/unreadable file degrades that half to the Noop/503
     * posture — NEVER a fallback to the pod's own SA (the pod runs as backups-effector).
     * The files are re-read per k8s request, so kubelet-rotated projected tokens are picked
     * up without a restart (fabric8 {@code OAuthTokenProvider}).
     */
    public static class K8s {

        /** The workload-console-read SA token file (the read half: list/inspect/logs/
         *  metrics/events/volumes/network). */
        private String readTokenFile = "/var/run/secrets/workload-console-read/token";

        /** The workload-console-mutate SA token file (the mutate half: delete/rollout-
         *  restart/exec/port-forward). */
        private String mutateTokenFile = "/var/run/secrets/workload-console-mutate/token";

        public String getReadTokenFile() {
            return readTokenFile;
        }

        public void setReadTokenFile(String readTokenFile) {
            this.readTokenFile = readTokenFile == null ? "" : readTokenFile;
        }

        public String getMutateTokenFile() {
            return mutateTokenFile;
        }

        public void setMutateTokenFile(String mutateTokenFile) {
            this.mutateTokenFile = mutateTokenFile == null ? "" : mutateTokenFile;
        }
    }

    /** A curated port-forward target. */
    public static class PortForwardTarget {
        private String namespace;
        private String workload;
        private int port;

        public String getNamespace() {
            return namespace;
        }

        public void setNamespace(String namespace) {
            this.namespace = namespace;
        }

        public String getWorkload() {
            return workload;
        }

        public void setWorkload(String workload) {
            this.workload = workload;
        }

        public int getPort() {
            return port;
        }

        public void setPort(int port) {
            this.port = port;
        }

        boolean matches(String ns, String wl, int p) {
            return namespace != null && namespace.equals(ns)
                    && workload != null && workload.equals(wl)
                    && port == p;
        }
    }
}
