package systems.hugmesh.adminbff.platform;

import io.fabric8.kubernetes.client.KubernetesClientException;
import org.junit.jupiter.api.Test;
import systems.hugmesh.adminbff.platform.Fabric8PlatformCapabilityProbe.K8sReader;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * The read-only, FAIL-SAFE contract of the real fabric8 platform-capability probe. The three k8s
 * primitives are mocked through the {@link K8sReader} seam (so the fail-safe COMPOSITION is tested
 * without the heavily-generic fabric8 fluent DSL): each test asserts ONE probe (ArgoCD / Velero /
 * build-node) resolves to the right boolean and that EVERY error path (no client, denied read,
 * missing CRD + missing Deployment) yields {@code false} + a warning and NEVER throws.
 *
 * <p>{@code null} from a primitive = "could-not-detect"; {@code false} = "read succeeded, absent".
 */
class Fabric8PlatformCapabilityProbeTest {

    /** Drives the unit-tested composition over a mocked reader, fresh warnings list each call. */
    private static PlatformCapabilityProbe.Result probe(K8sReader reader) {
        // ClientFactory is irrelevant here — we call the seam-overload directly.
        Fabric8PlatformCapabilityProbe p = new Fabric8PlatformCapabilityProbe(() -> null);
        return p.probe(reader, new ArrayList<>());
    }

    /** A reader where everything is cleanly ABSENT (reads succeed, infra not installed). */
    private static K8sReader absentReader() {
        K8sReader r = mock(K8sReader.class);
        when(r.crdInstalled(anyString())).thenReturn(false);
        when(r.deploymentPresent(anyString(), anyString())).thenReturn(false);
        when(r.nodeLabels()).thenReturn(List.of());
        return r;
    }

    // ── meta ─────────────────────────────────────────────────────────────────────────────

    @Test
    void isReal_isTrue() {
        assertThat(new Fabric8PlatformCapabilityProbe(() -> null).isReal()).isTrue();
    }

    // ── all absent ─────────────────────────────────────────────────────────────────────────

    @Test
    void allAbsent_everythingFalse_noWarnings() {
        PlatformCapabilityProbe.Result r = probe(absentReader());
        assertThat(r.argocdPresent()).isFalse();
        assertThat(r.veleroPresent()).isFalse();
        assertThat(r.buildNodePresent()).isFalse();
        // clean ABSENT (reads succeeded, infra simply not installed) is NOT a warning.
        assertThat(r.warnings()).isEmpty();
    }

    // ── argocd ───────────────────────────────────────────────────────────────────────────

    @Test
    void argocd_presentViaCrd() {
        K8sReader r = absentReader();
        when(r.crdInstalled(Fabric8PlatformCapabilityProbe.ARGOCD_CRD)).thenReturn(true);
        assertThat(probe(r).argocdPresent()).isTrue();
    }

    @Test
    void argocd_presentViaDeployment() {
        K8sReader r = absentReader();
        when(r.deploymentPresent(Fabric8PlatformCapabilityProbe.ARGOCD_NAMESPACE,
                Fabric8PlatformCapabilityProbe.ARGOCD_DEPLOYMENT)).thenReturn(true);
        assertThat(probe(r).argocdPresent()).isTrue();
    }

    // ── velero ───────────────────────────────────────────────────────────────────────────

    @Test
    void velero_presentViaCrd() {
        K8sReader r = absentReader();
        when(r.crdInstalled(Fabric8PlatformCapabilityProbe.VELERO_CRD)).thenReturn(true);
        assertThat(probe(r).veleroPresent()).isTrue();
    }

    @Test
    void velero_presentViaDeployment() {
        K8sReader r = absentReader();
        when(r.deploymentPresent(Fabric8PlatformCapabilityProbe.VELERO_NAMESPACE,
                Fabric8PlatformCapabilityProbe.VELERO_DEPLOYMENT)).thenReturn(true);
        assertThat(probe(r).veleroPresent()).isTrue();
    }

    // ── build node ─────────────────────────────────────────────────────────────────────────

    @Test
    void buildNode_presentWhenLabelledAmd64() {
        K8sReader r = absentReader();
        when(r.nodeLabels()).thenReturn(List.of(Map.of(
                Fabric8PlatformCapabilityProbe.BUILD_NODE_LABEL, "true",
                Fabric8PlatformCapabilityProbe.ARCH_LABEL, "amd64")));
        assertThat(probe(r).buildNodePresent()).isTrue();
    }

    @Test
    void buildNode_absentWhenLabelledButNotAmd64() {
        // a Pi mistakenly carrying the build label must NOT count — arch guard.
        K8sReader r = absentReader();
        when(r.nodeLabels()).thenReturn(List.of(Map.of(
                Fabric8PlatformCapabilityProbe.BUILD_NODE_LABEL, "true",
                Fabric8PlatformCapabilityProbe.ARCH_LABEL, "arm64")));
        assertThat(probe(r).buildNodePresent()).isFalse();
    }

    @Test
    void buildNode_absentWhenAmd64ButUnlabelled() {
        K8sReader r = absentReader();
        when(r.nodeLabels()).thenReturn(List.of(Map.of(
                Fabric8PlatformCapabilityProbe.ARCH_LABEL, "amd64")));
        assertThat(probe(r).buildNodePresent()).isFalse();
    }

    // ── fail-safe: no client (the ClientFactory throws) ──────────────────────────────────────

    @Test
    void noClient_allFalse_withWarning_noException() {
        Fabric8PlatformCapabilityProbe probe = new Fabric8PlatformCapabilityProbe(() -> {
            throw new KubernetesClientException("no in-cluster config");
        });
        PlatformCapabilityProbe.Result r = probe.probe();
        assertThat(r.argocdPresent()).isFalse();
        assertThat(r.veleroPresent()).isFalse();
        assertThat(r.buildNodePresent()).isFalse();
        assertThat(r.warnings()).anyMatch(w -> w.contains("Kubernetes client unavailable"));
    }

    // ── fail-safe: k8s denied (every primitive returns null / throws) ────────────────────────

    @Test
    void k8sDenied_allFalse_withWarnings_noException() {
        K8sReader r = mock(K8sReader.class);
        when(r.crdInstalled(anyString())).thenReturn(null);          // CRD read denied
        when(r.deploymentPresent(anyString(), anyString())).thenReturn(null); // dep read denied
        when(r.nodeLabels()).thenThrow(new KubernetesClientException("forbidden")); // node list denied

        PlatformCapabilityProbe.Result result = probe(r);
        assertThat(result.argocdPresent()).isFalse();
        assertThat(result.veleroPresent()).isFalse();
        assertThat(result.buildNodePresent()).isFalse();
        // ArgoCD + Velero (both null) + build-node (threw) = 3 warnings.
        assertThat(result.warnings()).hasSize(3);
        assertThat(result.warnings()).anyMatch(w -> w.contains("ArgoCD"));
        assertThat(result.warnings()).anyMatch(w -> w.contains("Velero"));
        assertThat(result.warnings()).anyMatch(w -> w.contains("build-node"));
    }

    // ── per-lookup fail-safe: CRD errors but Deployment present still resolves TRUE ──────────

    @Test
    void crdErrorButDeploymentPresent_stillTrue() {
        K8sReader r = absentReader();
        when(r.crdInstalled(Fabric8PlatformCapabilityProbe.ARGOCD_CRD)).thenReturn(null); // errored
        when(r.deploymentPresent(Fabric8PlatformCapabilityProbe.ARGOCD_NAMESPACE,
                Fabric8PlatformCapabilityProbe.ARGOCD_DEPLOYMENT)).thenReturn(true);
        PlatformCapabilityProbe.Result result = probe(r);
        assertThat(result.argocdPresent()).isTrue();
        // a successful detection via the fallback path produces NO warning.
        assertThat(result.warnings()).isEmpty();
    }

    // ── noop probe ───────────────────────────────────────────────────────────────────────

    @Test
    void noopProbe_isNotReal_allFalse_withWarning() {
        PlatformCapabilityProbe probe = new NoopPlatformCapabilityProbe();
        assertThat(probe.isReal()).isFalse();
        PlatformCapabilityProbe.Result r = probe.probe();
        assertThat(r.argocdPresent()).isFalse();
        assertThat(r.veleroPresent()).isFalse();
        assertThat(r.buildNodePresent()).isFalse();
        assertThat(r.warnings()).contains(NoopPlatformCapabilityProbe.NOT_WIRED_WARNING);
    }
}
