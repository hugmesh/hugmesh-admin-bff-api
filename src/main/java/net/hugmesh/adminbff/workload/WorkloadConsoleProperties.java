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
 * Lease + device/SSH-license, not by this list.
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

    /** The read-only exec command allowlist (first token matched). */
    private List<String> execReadOnlyCommands = new ArrayList<>();

    /** Default grant TTL in hours (DECISION 4/6, ~24h). */
    private long grantTtlHours = 24;

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

    /** True iff the first command token is on the read-only exec allowlist. */
    public boolean execReadOnlyAllowed(List<String> command) {
        if (command == null || command.isEmpty()) return false;
        String head = command.get(0);
        return head != null && execReadOnlyCommands.contains(head);
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
