package net.hugmesh.adminbff.testreports;

import io.fabric8.kubernetes.client.KubernetesClientException;
import org.junit.jupiter.api.Test;
import net.hugmesh.commons.web.ApiException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Launcher seam behaviour: the cluster-less Noop returns a synthetic Job name +
 * reports {@code isReal()==false} (the prod-hygiene gate signal), and the real
 * fabric8 launcher maps a cluster-side rejection to a 502 {@link ApiException}
 * (never a raw 500 leaking a stack trace to the admin-ui). The happy fabric8 apply
 * is covered end-to-end by the cluster; here we assert the error contract via a
 * throwing client factory.
 */
class JobLauncherTest {

    @Test
    void noopLauncher_isNotReal_andReturnsSyntheticName() {
        JobLauncher launcher = new NoopJobLauncher();
        assertThat(launcher.isReal()).isFalse();
        assertThat(launcher.apply("apiVersion: batch/v1\nkind: Job\n", "run-9").block())
                .isEqualTo("hugmesh-test-runner-run-9");
    }

    @Test
    void fabric8Launcher_isReal() {
        Fabric8JobLauncher launcher = new Fabric8JobLauncher(
                () -> { throw new KubernetesClientException("no cluster"); }, "hugmesh-backend");
        assertThat(launcher.isReal()).isTrue();
    }

    @Test
    void fabric8Launcher_clusterRejection_mapsToBadGateway() {
        Fabric8JobLauncher launcher = new Fabric8JobLauncher(
                () -> { throw new KubernetesClientException("forbidden: jobs is forbidden"); },
                "hugmesh-backend");
        assertThatThrownBy(() -> launcher.apply("kind: Job\n", "run-1").block())
                .isInstanceOf(ApiException.class)
                .satisfies(e -> assertThat(((ApiException) e).status().value()).isEqualTo(502))
                .hasMessageContaining("could not launch test-runner Job");
    }

    @Test
    void fabric8Launcher_genericError_mapsToBadGateway() {
        Fabric8JobLauncher launcher = new Fabric8JobLauncher(
                () -> { throw new RuntimeException("boom"); }, "hugmesh-backend");
        assertThatThrownBy(() -> launcher.apply("kind: Job\n", "run-1").block())
                .isInstanceOf(ApiException.class)
                .satisfies(e -> assertThat(((ApiException) e).status().value()).isEqualTo(502));
    }

    @Test
    void fabric8Launcher_blankNamespace_defaultsToBackend() {
        // construction with a blank namespace falls back to hugmesh-backend (no NPE).
        Fabric8JobLauncher launcher = new Fabric8JobLauncher(
                () -> { throw new RuntimeException("x"); }, "  ");
        assertThat(launcher.isReal()).isTrue();
    }
}
