package net.hugmesh.adminbff.argocd;

import io.netty.handler.ssl.ClientAuth;
import net.hugmesh.adminbff.config.TestPki;
import net.hugmesh.adminbff.config.TlsTestServer;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;

import java.nio.file.Path;
import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * hugmesh-admin-bff-api#62 (decisions 81a = A, 81b = B), proven with a REAL TLS handshake
 * against an in-test ArgoCD API stand-in on 127.0.0.1 that asks for no client certificate
 * (argocd-server does not). The client under test is the bean {@link ArgoCdConfig} wires.
 *
 * <ul>
 *   <li>Positive: a server certificate issued by the cluster CA (what 81b = B makes
 *       hugmesh-generator issue for argocd-server) is accepted through the shared
 *       {@code hugmesh.mtls.client} truststore — no ArgoCD special case. RED on the pre-fix
 *       code, whose bare {@code WebClient.builder()} used the JDK truststore (the
 *       {@code enabled=false} case below).</li>
 *   <li>Negative control: ArgoCD's stock SELF-SIGNED {@code O=Argo CD} certificate — the one
 *       measured in-pod on 2026-09-17 — is still refused, even with the truststore loaded. The
 *       self-signed cert is deliberately NOT imported anywhere.</li>
 * </ul>
 */
class ArgoCdClientMtlsTest {

    private static final String PW = "changeit";
    private static final Duration WAIT = Duration.ofSeconds(20);

    @TempDir
    static Path dir;

    static TestPki.Issued clusterCa;
    static Path keyStore;
    static Path trustStore;

    @BeforeAll
    static void pki() throws Exception {
        clusterCa = TestPki.ca("hugmesh test cluster CA");
        TestPki.Issued podIdentity = TestPki.clientLeaf(clusterCa, "hugmesh-admin-bff-api");
        keyStore = TestPki.keyStore(dir, "keystore.p12", PW, podIdentity, clusterCa.cert());
        trustStore = TestPki.trustStore(dir, "truststore.p12", PW, clusterCa.cert());
    }

    private static ApplicationContextRunner runner(String baseUrl, boolean mtls) {
        ApplicationContextRunner r = new ApplicationContextRunner()
                .withUserConfiguration(ArgoCdConfig.class)
                .withPropertyValues(
                        "app.appstore.effector.enabled=true",
                        "app.appstore.argocd.base-url=" + baseUrl,
                        "app.appstore.argocd.auth-token=argocd-token");
        if (mtls) {
            r = r.withPropertyValues(
                    "hugmesh.mtls.client.enabled=true",
                    "hugmesh.mtls.client.key-store=" + keyStore,
                    "hugmesh.mtls.client.key-store-password=" + PW,
                    "hugmesh.mtls.client.trust-store=" + trustStore,
                    "hugmesh.mtls.client.trust-store-password=" + PW);
        }
        return r;
    }

    @Test
    void clusterCaIssuedArgoCdCertificate_isAcceptedThroughTheSharedTruststore() throws Exception {
        TestPki.Issued leaf = TestPki.serverLeaf(clusterCa, "argocd-server");
        try (TlsTestServer server = TlsTestServer.start(leaf,
                new java.security.cert.X509Certificate[] {clusterCa.cert()}, ClientAuth.NONE, null)) {
            runner(server.baseUrl(), true).run(ctx -> {
                ArgoCdClient client = ctx.getBean(ArgoCdClient.class);
                assertThat(client).isInstanceOf(RestArgoCdClient.class);
                assertThat(client.createApplication("svc-a", "https://git/x.git", "deploy", "main", "ns-a")
                        .block(WAIT)).isEqualTo("svc-a");
                assertThat(client.deleteApplication("svc-a").block(WAIT)).isTrue();
            });
            assertThat(server.seen()).hasSize(2);
            assertThat(server.seen().get(0).uri()).isEqualTo("/api/v1/applications?upsert=true");
            assertThat(server.seen().get(0).authorization()).isEqualTo("Bearer argocd-token");
        }
    }

    /** Negative control: ArgoCD's own self-signed leaf is refused — nothing imports it. */
    @Test
    void selfSignedArgoCdCertificate_isRefused_evenWithTheTruststoreLoaded() throws Exception {
        TestPki.Issued selfSigned = TestPki.selfSignedServer("O=Argo CD");
        try (TlsTestServer server = TlsTestServer.start(selfSigned,
                new java.security.cert.X509Certificate[0], ClientAuth.NONE, null)) {
            runner(server.baseUrl(), true).run(ctx -> {
                ArgoCdClient client = ctx.getBean(ArgoCdClient.class);
                assertThatThrownBy(() -> client.createApplication("svc-a", "https://git/x.git", "deploy",
                        "main", "ns-a").block(WAIT)).hasStackTraceContaining("SSL");
                // deleteApplication swallows transport errors into false (retry next tick).
                assertThat(client.deleteApplication("svc-a").block(WAIT)).isFalse();
            });
            assertThat(server.seen()).as("no request may reach HTTP over an untrusted handshake").isEmpty();
        }
    }

    /** The pre-fix behaviour (JDK trust): even a cluster-CA-issued ArgoCD cert is refused. */
    @Test
    void mtlsDisabled_jdkTrust_refusesEvenAClusterCaIssuedCertificate() throws Exception {
        TestPki.Issued leaf = TestPki.serverLeaf(clusterCa, "argocd-server");
        try (TlsTestServer server = TlsTestServer.start(leaf,
                new java.security.cert.X509Certificate[] {clusterCa.cert()}, ClientAuth.NONE, null)) {
            runner(server.baseUrl(), false).run(ctx -> {
                ArgoCdClient client = ctx.getBean(ArgoCdClient.class);
                assertThatThrownBy(() -> client.createApplication("svc-a", "https://git/x.git", "deploy",
                        "main", "ns-a").block(WAIT)).hasStackTraceContaining("SSL");
            });
            assertThat(server.seen()).isEmpty();
        }
    }
}
