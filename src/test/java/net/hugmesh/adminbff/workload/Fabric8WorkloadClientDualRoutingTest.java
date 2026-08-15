package net.hugmesh.adminbff.workload;

import io.fabric8.kubernetes.api.model.Pod;
import io.fabric8.kubernetes.api.model.PodBuilder;
import io.fabric8.kubernetes.client.Config;
import io.fabric8.kubernetes.client.ConfigBuilder;
import io.fabric8.kubernetes.client.KubernetesClient;
import io.fabric8.kubernetes.client.KubernetesClientBuilder;
import io.fabric8.kubernetes.client.server.mock.EnableKubernetesMockClient;
import io.fabric8.kubernetes.client.server.mock.KubernetesMockServer;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import reactor.test.StepVerifier;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The read-vs-mutate SA split against the fabric8 CRUD mock server (no cluster):
 * <ul>
 *   <li>every read rides the READ half and every mutation rides the MUTATE half — proven by
 *       darkening the OTHER half (null): any cross-routed call would 503 instead of reach the
 *       server;</li>
 *   <li>wire-level: a client built by the REAL
 *       {@link WorkloadConsoleClientConfig#buildDualSaClient} seam sends {@code Bearer
 *       <projected-token>} on every request, picks up an on-disk rotation WITHOUT a rebuild
 *       (kubelet-refreshed projected tokens), and NEVER sends the pod SA token that rides the
 *       autoconfigured base config.</li>
 * </ul>
 */
// https=false: the wire test builds its client through the REAL buildDualSaClient seam, whose
// least-privilege config carries only the base's CA coordinates (never trustCerts), so the
// mock server's self-signed default-HTTPS cert would be rejected — plain HTTP keeps the
// Authorization-header assertions exact without loosening the production config shape.
@EnableKubernetesMockClient(crud = true, https = false)
class Fabric8WorkloadClientDualRoutingTest {

    private static final Duration TIMEOUT = Duration.ofSeconds(10);
    private static final String POD_SA_TOKEN = "pod-sa-token-NEVER-ON-THE-WIRE";

    // Injected by the fabric8 JUnit5 extension (fresh mock server per test).
    KubernetesMockServer server;
    KubernetesClient client;

    private static Pod pod(String namespace, String name) {
        return new PodBuilder()
                .withNewMetadata().withNamespace(namespace).withName(name).endMetadata()
                .build();
    }

    private static void assertUnavailable503(Throwable t) {
        assertThat(t).isInstanceOf(WorkloadClientException.class);
        assertThat(((WorkloadClientException) t).isUnavailable())
                .as("dark half must 503 (unavailable), not 502").isTrue();
    }

    @Test
    void reads_rideTheReadHalfOnly_mutationsFailClosedWithoutTouchingIt() {
        client.pods().inNamespace("ns1").resource(pod("ns1", "p1")).create();
        var dual = new Fabric8WorkloadClient(client, null); // read half ONLY

        var pods = dual.listPods("ns1").collectList().block(TIMEOUT);
        assertThat(pods).extracting(WorkloadDtos.PodSummary::name).containsExactly("p1");

        // a mutation must NOT fall back onto the (privileged-to-read-only) read half
        StepVerifier.create(dual.deletePod("ns1", "p1"))
                .expectErrorSatisfies(Fabric8WorkloadClientDualRoutingTest::assertUnavailable503)
                .verify(TIMEOUT);
        assertThat(client.pods().inNamespace("ns1").withName("p1").get())
                .as("the dark mutate half must leave the pod untouched").isNotNull();
    }

    @Test
    void mutations_rideTheMutateHalfOnly_readsFailClosedWithoutTouchingIt() {
        client.pods().inNamespace("ns1").resource(pod("ns1", "p1")).create();
        var dual = new Fabric8WorkloadClient(null, client); // mutate half ONLY

        assertThat(dual.deletePod("ns1", "p1").block(TIMEOUT)).isEqualTo(1);
        assertThat(client.pods().inNamespace("ns1").withName("p1").get()).isNull();

        // a read must NOT fall back onto the (delete/exec-privileged) mutate half
        StepVerifier.create(dual.listPods("ns1"))
                .expectErrorSatisfies(Fabric8WorkloadClientDualRoutingTest::assertUnavailable503)
                .verify(TIMEOUT);
    }

    @Test
    void projectedToken_authenticatesEveryRequest_rotatesInPlace_podSaNeverOnTheWire(
            @TempDir Path dir) throws Exception {
        Path readTok = Files.writeString(dir.resolve("read-token"), "read-epoch-1");
        var k8s = new WorkloadConsoleProperties.K8s();
        k8s.setReadTokenFile(readTok.toString());
        k8s.setMutateTokenFile(dir.resolve("absent-mutate-token").toString());

        // the pod's autoconfigured base carries the POD SA token — it must never be sent
        Config base = new ConfigBuilder()
                .withMasterUrl(client.getConfiguration().getMasterUrl())
                .withOauthToken(POD_SA_TOKEN)
                .withAutoOAuthToken(POD_SA_TOKEN)
                .build();

        List<KubernetesClient> real = new ArrayList<>();
        WorkloadClient dual = WorkloadConsoleClientConfig.buildDualSaClient(k8s, () -> base,
                cfg -> {
                    var c = new KubernetesClientBuilder().withConfig(cfg).build();
                    real.add(c);
                    return c;
                });
        try {
            client.pods().inNamespace("ns1").resource(pod("ns1", "p1")).create();

            var pods = dual.listPods("ns1").collectList().block(TIMEOUT);
            assertThat(pods).hasSize(1);
            assertThat(server.getLastRequest().getHeader("Authorization"))
                    .isEqualTo("Bearer read-epoch-1");

            // kubelet rotates the projected token IN PLACE — the same client, no rebuild
            Files.writeString(readTok, "read-epoch-2");
            dual.listPods("ns1").collectList().block(TIMEOUT);
            assertThat(server.getLastRequest().getHeader("Authorization"))
                    .as("a rotated token must ride the very next request")
                    .isEqualTo("Bearer read-epoch-2");
        } finally {
            real.forEach(KubernetesClient::close);
        }
    }
}
