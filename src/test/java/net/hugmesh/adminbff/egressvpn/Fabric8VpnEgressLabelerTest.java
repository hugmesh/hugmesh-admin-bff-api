package net.hugmesh.adminbff.egressvpn;

import io.fabric8.kubernetes.api.model.Pod;
import io.fabric8.kubernetes.api.model.PodBuilder;
import io.fabric8.kubernetes.api.model.apps.Deployment;
import io.fabric8.kubernetes.api.model.apps.DeploymentBuilder;
import io.fabric8.kubernetes.api.model.apps.StatefulSet;
import io.fabric8.kubernetes.api.model.apps.StatefulSetBuilder;
import io.fabric8.kubernetes.client.KubernetesClient;
import io.fabric8.kubernetes.client.server.mock.EnableKubernetesMockClient;
import io.fabric8.kubernetes.client.server.mock.KubernetesMockServer;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import reactor.core.publisher.Flux;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * {@link Fabric8VpnEgressLabeler} convergence against the fabric8 CRUD mock server (no
 * cluster) — the REAL label edits a live sweep would apply:
 * <ul>
 *   <li>a slug-carrying assignment labels JUST that service's workload
 *       ({@code metadata.labels}, NEVER {@code spec.template} — restart-free) AND its live
 *       pods with {@code snapdragon.systems/vpn-egress=true} (the exact key/value the
 *       generator's {@code egress-vpn-interaction.yaml} podSelector matches);</li>
 *   <li>an all-services (null-slug) assignment labels the whole configured public trio;
 *       an unrelated workload is NEVER labelled;</li>
 *   <li>an emptied assignment set UN-labels (removes the key, never writes "false") and a
 *       stray labelled pod backed by no desired workload is swept clean;</li>
 *   <li>a cluster failure is swallowed to a 0 count (the admin mutation never fails).</li>
 * </ul>
 */
@EnableKubernetesMockClient(crud = true)
class Fabric8VpnEgressLabelerTest {

    private static final String NS = "hugmesh-backend";

    // Injected by the fabric8 JUnit5 extension (fresh mock server per test).
    KubernetesMockServer server;
    KubernetesClient client;

    private VpnNodeAssignmentRepository assignments;

    @BeforeEach
    void seedWorkloads() {
        assignments = mock(VpnNodeAssignmentRepository.class);
        client.apps().deployments().inNamespace(NS).resource(deployment("akkoma", "akkoma")).create();
        client.apps().deployments().inNamespace(NS)
                .resource(deployment("hugmesh-coturn", "hugmesh-coturn")).create();
        client.apps().deployments().inNamespace(NS).resource(deployment("frontend", "frontend")).create();
        client.apps().statefulSets().inNamespace(NS).resource(statefulSet("tuwunel", "tuwunel")).create();
        client.pods().inNamespace(NS).resource(pod("akkoma-0", "akkoma")).create();
        client.pods().inNamespace(NS).resource(pod("hugmesh-coturn-0", "hugmesh-coturn")).create();
        client.pods().inNamespace(NS).resource(pod("frontend-0", "frontend")).create();
        client.pods().inNamespace(NS).resource(pod("tuwunel-0", "tuwunel")).create();
    }

    private static Deployment deployment(String name, String appLabel) {
        return new DeploymentBuilder()
                .withNewMetadata().withName(name).endMetadata()
                .withNewSpec()
                .withNewSelector().addToMatchLabels("app", appLabel).endSelector()
                .withNewTemplate()
                .withNewMetadata().addToLabels("app", appLabel).endMetadata()
                .endTemplate()
                .endSpec()
                .build();
    }

    private static StatefulSet statefulSet(String name, String appLabel) {
        return new StatefulSetBuilder()
                .withNewMetadata().withName(name).endMetadata()
                .withNewSpec()
                .withNewSelector().addToMatchLabels("app", appLabel).endSelector()
                .withNewTemplate()
                .withNewMetadata().addToLabels("app", appLabel).endMetadata()
                .endTemplate()
                .endSpec()
                .build();
    }

    private static Pod pod(String name, String appLabel) {
        return new PodBuilder()
                .withNewMetadata().withName(name).addToLabels("app", appLabel).endMetadata()
                .build();
    }

    private static VpnNodeAssignment assignment(String slug) {
        return new VpnNodeAssignment("asg-" + slug, "cfg-1", VpnNodeAssignment.SCOPE_DOMAIN,
                null, "brandx", slug, VpnNodeAssignment.STATE_ACTIVE, "root", Instant.now(),
                null, null, "brandx", VpnNodeAssignment.PROP_PENDING, 1L);
    }

    private Fabric8VpnEgressLabeler labeler() {
        // A FRESH client per sweep — the labeler closes its client, and the extension-injected
        // `client` must stay open for the assertions below.
        return new Fabric8VpnEgressLabeler(() -> server.createClient(), assignments, NS,
                List.of("akkoma", "tuwunel", "coturn"));
    }

    private Map<String, String> deploymentLabels(String name) {
        return client.apps().deployments().inNamespace(NS).withName(name).get()
                .getMetadata().getLabels();
    }

    private Map<String, String> podLabels(String name) {
        return client.pods().inNamespace(NS).withName(name).get().getMetadata().getLabels();
    }

    // ── slug assignment -> just that service, meta + pods, never the template ─────────────

    @Test
    void slugAssignment_labelsJustThatWorkloadAndPods_restartFree() {
        when(assignments.listActiveAll()).thenReturn(Flux.just(assignment("coturn")));

        Long changed = labeler().reconcile().block();

        assertThat(changed).isEqualTo(2L); // the coturn Deployment meta + its one pod
        assertThat(deploymentLabels("hugmesh-coturn"))
                .containsEntry("snapdragon.systems/vpn-egress", "true");
        assertThat(podLabels("hugmesh-coturn-0"))
                .containsEntry("snapdragon.systems/vpn-egress", "true");
        // restart-free: the pod TEMPLATE is untouched (labelling it would roll the service).
        assertThat(client.apps().deployments().inNamespace(NS).withName("hugmesh-coturn").get()
                .getSpec().getTemplate().getMetadata().getLabels())
                .doesNotContainKey("snapdragon.systems/vpn-egress");
        // nothing else labelled.
        assertThat(deploymentLabels("akkoma")).isNullOrEmpty();
        assertThat(podLabels("akkoma-0")).doesNotContainKey("snapdragon.systems/vpn-egress");
        assertThat(deploymentLabels("frontend")).isNullOrEmpty();
    }

    // ── all-services assignment -> the configured public trio, never a bystander ──────────

    @Test
    void allServicesAssignment_labelsTheConfiguredTrio_neverABystander() {
        when(assignments.listActiveAll()).thenReturn(Flux.just(assignment(null)));

        Long changed = labeler().reconcile().block();

        // akkoma (Deployment meta + pod), hugmesh-coturn (meta + pod), tuwunel (STS meta + pod).
        assertThat(changed).isEqualTo(6L);
        assertThat(deploymentLabels("akkoma")).containsEntry("snapdragon.systems/vpn-egress", "true");
        assertThat(client.apps().statefulSets().inNamespace(NS).withName("tuwunel").get()
                .getMetadata().getLabels()).containsEntry("snapdragon.systems/vpn-egress", "true");
        assertThat(podLabels("akkoma-0")).containsEntry("snapdragon.systems/vpn-egress", "true");
        assertThat(podLabels("tuwunel-0")).containsEntry("snapdragon.systems/vpn-egress", "true");
        assertThat(podLabels("hugmesh-coturn-0")).containsEntry("snapdragon.systems/vpn-egress", "true");
        // the bystander stays unlabelled (fail-closed onto the Squid/default-deny path).
        assertThat(deploymentLabels("frontend")).isNullOrEmpty();
        assertThat(podLabels("frontend-0")).doesNotContainKey("snapdragon.systems/vpn-egress");
    }

    // ── emptied assignment set -> un-label (key REMOVED) + stray-pod sweep ────────────────

    @Test
    void emptiedAssignments_unlabelsEverything_removingTheKey() {
        when(assignments.listActiveAll()).thenReturn(Flux.just(assignment("coturn")));
        labeler().reconcile().block();
        assertThat(podLabels("hugmesh-coturn-0")).containsEntry("snapdragon.systems/vpn-egress", "true");

        when(assignments.listActiveAll()).thenReturn(Flux.empty());
        Long changed = labeler().reconcile().block();

        assertThat(changed).isEqualTo(2L); // meta + pod un-labelled
        assertThat(deploymentLabels("hugmesh-coturn")).doesNotContainKey("snapdragon.systems/vpn-egress");
        // the key is REMOVED, never flipped to "false" (the NetworkPolicy matches value "true";
        // a lingering key would still read as opted-in to a human).
        assertThat(podLabels("hugmesh-coturn-0")).doesNotContainKey("snapdragon.systems/vpn-egress");
    }

    @Test
    void strayLabelledPod_backedByNoDesiredWorkload_isSweptClean() {
        client.pods().inNamespace(NS).resource(new PodBuilder()
                .withNewMetadata().withName("stray-0")
                .addToLabels("app", "stray")
                .addToLabels("snapdragon.systems/vpn-egress", "true")
                .endMetadata().build()).create();
        when(assignments.listActiveAll()).thenReturn(Flux.empty());

        Long changed = labeler().reconcile().block();

        assertThat(changed).isEqualTo(1L);
        assertThat(podLabels("stray-0")).doesNotContainKey("snapdragon.systems/vpn-egress");
    }

    // ── convergence: a second identical sweep is a no-op ──────────────────────────────────

    @Test
    void secondSweep_isIdempotent_zeroChanges() {
        when(assignments.listActiveAll()).thenReturn(Flux.just(assignment("coturn")));
        assertThat(labeler().reconcile().block()).isEqualTo(2L);

        when(assignments.listActiveAll()).thenReturn(Flux.just(assignment("coturn")));
        assertThat(labeler().reconcile().block()).isEqualTo(0L);
    }

    // ── failure is swallowed to 0 (the triggering admin mutation never fails) ─────────────

    @Test
    void clusterFailure_isSwallowedToZero() {
        when(assignments.listActiveAll()).thenReturn(Flux.just(assignment("coturn")));
        Fabric8VpnEgressLabeler broken = new Fabric8VpnEgressLabeler(
                () -> { throw new io.fabric8.kubernetes.client.KubernetesClientException("no cluster"); },
                assignments, NS, List.of("akkoma", "tuwunel", "coturn"));

        assertThat(broken.reconcile().block()).isEqualTo(0L);
    }

    // ── the pure slug/label resolution rules ──────────────────────────────────────────────

    @Test
    void desiredSlugs_slugContributesItself_nullSlugContributesTheTrio() {
        List<String> trio = List.of("akkoma", "tuwunel", "coturn");
        assertThat(Fabric8VpnEgressLabeler.desiredSlugs(List.of(assignment("coturn")), trio))
                .containsExactly("coturn");
        assertThat(Fabric8VpnEgressLabeler.desiredSlugs(List.of(assignment(null)), trio))
                .containsExactlyInAnyOrderElementsOf(trio);
        assertThat(Fabric8VpnEgressLabeler.desiredSlugs(List.of(), trio)).isEmpty();
    }

    @Test
    void wantsLabel_matchesName_hugmeshPrefixedName_andAppKubernetesIoName() {
        assertThat(Fabric8VpnEgressLabeler.wantsLabel(deployment("akkoma", "x"), Set.of("akkoma"))).isTrue();
        assertThat(Fabric8VpnEgressLabeler.wantsLabel(deployment("hugmesh-coturn", "x"), Set.of("coturn"))).isTrue();
        Deployment byLabel = new DeploymentBuilder(deployment("other-name", "x"))
                .editMetadata().addToLabels("app.kubernetes.io/name", "tuwunel").endMetadata().build();
        assertThat(Fabric8VpnEgressLabeler.wantsLabel(byLabel, Set.of("tuwunel"))).isTrue();
        assertThat(Fabric8VpnEgressLabeler.wantsLabel(deployment("frontend", "x"), Set.of("coturn"))).isFalse();
    }
}
