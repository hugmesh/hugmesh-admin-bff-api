package net.hugmesh.adminbff.workload;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/** The generator-curated allowlists + gate semantics (fail-closed). */
class WorkloadConsolePropertiesTest {

    @Test
    void defaults_areDark_andFailClosed() {
        WorkloadConsoleProperties p = new WorkloadConsoleProperties();
        assertThat(p.isEnabled()).isFalse();
        // empty allowlist rejects every namespace (fail-closed)
        assertThat(p.namespaceAllowed("hugmesh-app")).isFalse();
        assertThat(p.namespaceAllowed(null)).isFalse();
        assertThat(p.portForwardAllowed("ns", "wl", 8080)).isFalse();
        assertThat(p.execReadOnlyAllowed(List.of("ls"))).isFalse();
    }

    @Test
    void namespaceAllowlist_membership() {
        WorkloadConsoleProperties p = new WorkloadConsoleProperties();
        p.setNamespaceAllowlist(List.of("hugmesh-app", "hugmesh-forum"));
        assertThat(p.namespaceAllowed("hugmesh-app")).isTrue();
        assertThat(p.namespaceAllowed("hugmesh-pki")).isFalse(); // infra tier excluded
    }

    @Test
    void portForwardAllowlist_exactTripleMatch() {
        WorkloadConsoleProperties p = new WorkloadConsoleProperties();
        var t = new WorkloadConsoleProperties.PortForwardTarget();
        t.setNamespace("hugmesh-app");
        t.setWorkload("web");
        t.setPort(8080);
        p.setPortForwardAllowlist(List.of(t));
        assertThat(p.portForwardAllowed("hugmesh-app", "web", 8080)).isTrue();
        assertThat(p.portForwardAllowed("hugmesh-app", "web", 5432)).isFalse(); // wrong port
        assertThat(p.portForwardAllowed("hugmesh-pki", "web", 8080)).isFalse();
    }

    @Test
    void execReadOnly_firstTokenAllowlist() {
        WorkloadConsoleProperties p = new WorkloadConsoleProperties();
        p.setExecReadOnlyCommands(List.of("ls", "cat", "ps"));
        assertThat(p.execReadOnlyAllowed(List.of("ls", "-la"))).isTrue();
        assertThat(p.execReadOnlyAllowed(List.of("rm", "-rf", "/"))).isFalse();
    }
}
