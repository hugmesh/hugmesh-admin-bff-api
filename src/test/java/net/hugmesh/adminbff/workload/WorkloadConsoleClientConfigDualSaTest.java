package net.hugmesh.adminbff.workload;

import io.fabric8.kubernetes.client.Config;
import io.fabric8.kubernetes.client.ConfigBuilder;
import io.fabric8.kubernetes.client.KubernetesClient;
import io.fabric8.kubernetes.client.OAuthTokenProvider;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import reactor.test.StepVerifier;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;

/**
 * The dual-SA config seam ({@link WorkloadConsoleClientConfig#buildDualSaClient}): each half's
 * client is bound to ITS projected token file, an absent half degrades to the Noop/503 posture,
 * and — the least-privilege core — the pod's own SA can NEVER authenticate a console call:
 * <ul>
 *   <li>both tokens present → both halves live, each config's SOLE credential is its
 *       file-re-reading {@link OAuthTokenProvider} (no static token, no client cert/key, no
 *       autoconfigure flag that would re-read the pod SA token on copy);</li>
 *   <li>one token absent → that half 503s on EVERY call, the other stays live, and NO second
 *       fabric8 client is built;</li>
 *   <li>both absent → the {@link NoopWorkloadClient} itself, and NO fabric8 client is EVER
 *       built (there is no pod-SA fallback path at all);</li>
 *   <li>rotation → the provider re-reads the file per request; a vanished/blank file raises
 *       the fail-closed 503 unavailable, never a fallback credential.</li>
 * </ul>
 */
class WorkloadConsoleClientConfigDualSaTest {

    private static final String POD_SA_TOKEN = "pod-sa-token-NEVER-A-CONSOLE-CREDENTIAL";

    /**
     * The pod's autoconfigured in-cluster config, faithful to production: it CARRIES the pod
     * SA credential (backups-effector) and the autoConfigure flag (a copied config would
     * re-run autoConfigure and re-read the pod SA token — the exact channel the from-empty
     * build closes).
     */
    private static Config podSaBase() {
        Config base = new ConfigBuilder()
                .withMasterUrl("https://k8s.internal:6443")
                .withCaCertFile("/var/run/secrets/kubernetes.io/serviceaccount/ca.crt")
                .withNamespace("hugmesh-backend")
                .withOauthToken(POD_SA_TOKEN)
                .withAutoOAuthToken(POD_SA_TOKEN)
                .withClientCertFile("/pod/client.crt")
                .withClientKeyFile("/pod/client.key")
                .build();
        // set AFTER build (the builder would autoconfigure from this box's environment)
        base.setAutoConfigure(true);
        return base;
    }

    private static WorkloadConsoleProperties.K8s k8s(Path readTokenFile, Path mutateTokenFile) {
        var k8s = new WorkloadConsoleProperties.K8s();
        k8s.setReadTokenFile(readTokenFile.toString());
        k8s.setMutateTokenFile(mutateTokenFile.toString());
        return k8s;
    }

    private static WorkloadClient build(WorkloadConsoleProperties.K8s k8s, List<Config> built) {
        return WorkloadConsoleClientConfig.buildDualSaClient(
                k8s,
                WorkloadConsoleClientConfigDualSaTest::podSaBase,
                cfg -> {
                    built.add(cfg);
                    return mock(KubernetesClient.class);
                });
    }

    private static void assertUnavailable503(Throwable t) {
        assertThat(t).isInstanceOf(WorkloadClientException.class);
        assertThat(((WorkloadClientException) t).isUnavailable())
                .as("dark half must 503 (unavailable), not 502").isTrue();
    }

    @Test
    void bothTokensPresent_bothHalvesLive_projectedTokenIsSoleCredential(@TempDir Path dir)
            throws IOException {
        Path readTok = Files.writeString(dir.resolve("read-token"), "read-tok-1\n");
        Path mutateTok = Files.writeString(dir.resolve("mutate-token"), "mutate-tok-1");
        List<Config> built = new ArrayList<>();

        WorkloadClient client = build(k8s(readTok, mutateTok), built);

        assertThat(client).isInstanceOf(Fabric8WorkloadClient.class);
        var dual = (Fabric8WorkloadClient) client;
        assertThat(dual.available()).isTrue();
        assertThat(dual.readHalfAvailable()).isTrue();
        assertThat(dual.mutateHalfAvailable()).isTrue();

        assertThat(built).as("one client per half, read first").hasSize(2);
        assertThat(built.get(0).getOauthTokenProvider().getToken()).isEqualTo("read-tok-1");
        assertThat(built.get(1).getOauthTokenProvider().getToken()).isEqualTo("mutate-tok-1");
        for (Config cfg : built) {
            // the cluster coordinates ride over from the autoconfigured base…
            assertThat(cfg.getMasterUrl()).startsWith("https://k8s.internal:6443");
            assertThat(cfg.getCaCertFile())
                    .isEqualTo("/var/run/secrets/kubernetes.io/serviceaccount/ca.crt");
            assertThat(cfg.getNamespace()).isEqualTo("hugmesh-backend");
            // …but NO pod-SA credential does: the provider is the SOLE credential
            assertThat(cfg.getOauthToken()).as("no static pod-SA token").isNull();
            assertThat(cfg.getAutoOAuthToken()).as("no autoconfigured pod-SA token").isNull();
            assertThat(cfg.getClientCertFile()).isNull();
            assertThat(cfg.getClientCertData()).isNull();
            assertThat(cfg.getClientKeyFile()).isNull();
            assertThat(cfg.getClientKeyData()).isNull();
            // and the flag that would make fabric8 re-read the pod SA token is NOT carried
            assertThat(cfg.getAutoConfigure())
                    .as("per-half config must never be autoconfigure-armed (pod-SA channel)")
                    .isNotEqualTo(Boolean.TRUE);
        }
    }

    @Test
    void mutateTokenAbsent_mutateHalf503sEveryCall_readHalfLive(@TempDir Path dir)
            throws IOException {
        Path readTok = Files.writeString(dir.resolve("read-token"), "read-tok");
        List<Config> built = new ArrayList<>();

        WorkloadClient client = build(k8s(readTok, dir.resolve("absent-mutate-token")), built);

        assertThat(client).isInstanceOf(Fabric8WorkloadClient.class);
        var dual = (Fabric8WorkloadClient) client;
        assertThat(dual.readHalfAvailable()).isTrue();
        assertThat(dual.mutateHalfAvailable()).isFalse();
        assertThat(built).as("ONLY the read half is built — no client for the absent token")
                .hasSize(1);

        // every runtime mutation degrades to the Noop/503 posture — never the read half,
        // never the pod SA
        StepVerifier.create(dual.deletePod("ns", "p"))
                .expectErrorSatisfies(WorkloadConsoleClientConfigDualSaTest::assertUnavailable503)
                .verify();
        StepVerifier.create(dual.deleteWorkloadPods("ns", "wl"))
                .expectErrorSatisfies(WorkloadConsoleClientConfigDualSaTest::assertUnavailable503)
                .verify();
        StepVerifier.create(dual.execReadOnly("ns", "p", "c", List.of("ls")))
                .expectErrorSatisfies(WorkloadConsoleClientConfigDualSaTest::assertUnavailable503)
                .verify();
        StepVerifier.create(dual.openExec("ns", "p", "c", List.of("sh")))
                .expectErrorSatisfies(WorkloadConsoleClientConfigDualSaTest::assertUnavailable503)
                .verify();
        StepVerifier.create(dual.rescheduleAfterExec("ns", "p"))
                .expectErrorSatisfies(WorkloadConsoleClientConfigDualSaTest::assertUnavailable503)
                .verify();
        StepVerifier.create(dual.openPortForward("ns", "wl", 8080))
                .expectErrorSatisfies(WorkloadConsoleClientConfigDualSaTest::assertUnavailable503)
                .verify();
    }

    @Test
    void readTokenAbsent_readHalf503sEveryCall_mutateHalfLive(@TempDir Path dir)
            throws IOException {
        Path mutateTok = Files.writeString(dir.resolve("mutate-token"), "mutate-tok");
        List<Config> built = new ArrayList<>();

        WorkloadClient client = build(k8s(dir.resolve("absent-read-token"), mutateTok), built);

        assertThat(client).isInstanceOf(Fabric8WorkloadClient.class);
        var dual = (Fabric8WorkloadClient) client;
        assertThat(dual.readHalfAvailable()).isFalse();
        assertThat(dual.mutateHalfAvailable()).isTrue();
        assertThat(built).hasSize(1);

        StepVerifier.create(dual.listPods("ns"))
                .expectErrorSatisfies(WorkloadConsoleClientConfigDualSaTest::assertUnavailable503)
                .verify();
        StepVerifier.create(dual.inspectPod("ns", "p"))
                .expectErrorSatisfies(WorkloadConsoleClientConfigDualSaTest::assertUnavailable503)
                .verify();
        StepVerifier.create(dual.namespaceDomain("ns"))
                .expectErrorSatisfies(WorkloadConsoleClientConfigDualSaTest::assertUnavailable503)
                .verify();
        // podMetrics swallows metrics-server absence — but a DARK READ HALF must still 503
        StepVerifier.create(dual.podMetrics("ns"))
                .expectErrorSatisfies(WorkloadConsoleClientConfigDualSaTest::assertUnavailable503)
                .verify();
        StepVerifier.create(dual.events("ns"))
                .expectErrorSatisfies(WorkloadConsoleClientConfigDualSaTest::assertUnavailable503)
                .verify();
        StepVerifier.create(dual.volumes("ns"))
                .expectErrorSatisfies(WorkloadConsoleClientConfigDualSaTest::assertUnavailable503)
                .verify();
        StepVerifier.create(dual.network("ns"))
                .expectErrorSatisfies(WorkloadConsoleClientConfigDualSaTest::assertUnavailable503)
                .verify();
        StepVerifier.create(dual.readLog("ns", "p", "c", 10))
                .expectErrorSatisfies(WorkloadConsoleClientConfigDualSaTest::assertUnavailable503)
                .verify();
        StepVerifier.create(dual.streamLog("ns", "p", "c"))
                .expectErrorSatisfies(WorkloadConsoleClientConfigDualSaTest::assertUnavailable503)
                .verify();
    }

    @Test
    void bothTokensAbsent_noopClient_andNoFabric8ClientIsEverBuilt(@TempDir Path dir) {
        List<Config> built = new ArrayList<>();

        WorkloadClient client = build(k8s(dir.resolve("no-read"), dir.resolve("no-mutate")), built);

        assertThat(client).isInstanceOf(NoopWorkloadClient.class);
        assertThat(client.available()).isFalse();
        // the structural no-fallback proof: with no projected token there is NOTHING to build
        // a client from — the pod SA path does not exist
        assertThat(built).as("no fabric8 client may EVER be built without a projected token")
                .isEmpty();
    }

    @Test
    void provider_reReadsRotatedToken_and503sOnVanishedOrBlankFile(@TempDir Path dir)
            throws IOException {
        Path readTok = Files.writeString(dir.resolve("read-token"), "epoch-1");
        Path mutateTok = Files.writeString(dir.resolve("mutate-token"), "m-1");
        List<Config> built = new ArrayList<>();
        build(k8s(readTok, mutateTok), built);
        OAuthTokenProvider provider = built.get(0).getOauthTokenProvider();

        assertThat(provider.getToken()).isEqualTo("epoch-1");
        // kubelet rotates the projected token in place — the NEXT request must carry it
        Files.writeString(readTok, "epoch-2\n");
        assertThat(provider.getToken()).isEqualTo("epoch-2");

        // a blank file is an unpopulated Secret — fail-closed 503, never no-auth/pod-SA
        Files.writeString(readTok, "");
        assertThatThrownBy(provider::getToken)
                .isInstanceOf(WorkloadClientException.class)
                .matches(t -> ((WorkloadClientException) t).isUnavailable());

        // a vanished file mid-flight — same 503 posture
        Files.delete(readTok);
        assertThatThrownBy(provider::getToken)
                .isInstanceOf(WorkloadClientException.class)
                .matches(t -> ((WorkloadClientException) t).isUnavailable());
    }
}
