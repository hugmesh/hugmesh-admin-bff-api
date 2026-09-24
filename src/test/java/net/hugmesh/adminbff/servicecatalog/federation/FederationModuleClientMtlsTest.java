package net.hugmesh.adminbff.servicecatalog.federation;

import io.netty.handler.ssl.ClientAuth;
import net.hugmesh.adminbff.config.TestPki;
import net.hugmesh.adminbff.config.TlsTestServer;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;

import java.nio.file.Path;
import java.security.cert.X509Certificate;
import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * hugmesh-admin-bff-api#82 (decision 81a = A), proven with a REAL TLS handshake: an in-test
 * federation-api stand-in on 127.0.0.1 whose certificate chains to a test "cluster CA" and which
 * REQUIRES a client certificate (the {@code SSL_CLIENT_AUTH=need} posture measured in-pod on
 * 2026-09-17). The client under test is the bean {@link FederationModuleClientConfig} wires, so
 * the {@code hugmesh.mtls.client.*} binding is exercised too.
 *
 * <p>RED on the pre-fix code: {@code RestFederationModuleClient} was a bare
 * {@code WebClient.builder()} (JDK trust, no client certificate), which is exactly the
 * {@code hugmesh.mtls.client.enabled=false} case below — the handshake fails before the Bearer
 * token is sent.
 */
class FederationModuleClientMtlsTest {

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

    private static ApplicationContextRunner runner(String baseUrl, String... extra) {
        return new ApplicationContextRunner()
                .withUserConfiguration(FederationModuleClientConfig.class)
                .withPropertyValues(
                        "app.appstore.federation.enabled=true",
                        "app.appstore.federation.base-url=" + baseUrl,
                        "app.appstore.federation.auth-token=superadmin-jwt")
                .withPropertyValues(extra);
    }

    private static String[] mtlsOn() {
        return new String[] {
                "hugmesh.mtls.client.enabled=true",
                "hugmesh.mtls.client.key-store=" + keyStore,
                "hugmesh.mtls.client.key-store-password=" + PW,
                "hugmesh.mtls.client.trust-store=" + trustStore,
                "hugmesh.mtls.client.trust-store-password=" + PW};
    }

    private static TlsTestServer federationApi(TestPki.Issued serverLeaf, X509Certificate... chain)
            throws Exception {
        return TlsTestServer.start(serverLeaf, chain, ClientAuth.REQUIRE, clusterCa.cert());
    }

    @Test
    void mtlsEnabled_presentsThePodIdentity_andRegistersAgainstAClientAuthNeedServer() throws Exception {
        TestPki.Issued leaf = TestPki.serverLeaf(clusterCa, "hugmesh-federation-api");
        try (TlsTestServer server = federationApi(leaf, clusterCa.cert())) {
            runner(server.baseUrl(), mtlsOn()).run(ctx -> {
                FederationModuleClient client = ctx.getBean(FederationModuleClient.class);
                assertThat(client).isInstanceOf(RestFederationModuleClient.class);
                String slug = client.registerModule("wiki", "Wiki", "ui", "https://x/remoteEntry.json",
                        "./Module", "1.0.0", "public", true, null).block(WAIT);
                assertThat(slug).isEqualTo("echo");
                assertThat(client.unregisterModule("wiki").block(WAIT)).isTrue();
            });
            assertThat(server.seen()).hasSize(2);
            TlsTestServer.Seen first = server.seen().get(0);
            assertThat(first.method()).isEqualTo("POST");
            assertThat(first.uri()).isEqualTo(RestFederationModuleClient.MODULES_PATH);
            // The pod's client certificate reached the server, and the Bearer rode on top of it.
            assertThat(first.clientSubject()).isEqualTo("CN=hugmesh-admin-bff-api");
            assertThat(first.authorization()).isEqualTo("Bearer superadmin-jwt");
        }
    }

    /** The pre-fix behaviour: no client cert, JDK trust — the call dies in the handshake. */
    @Test
    void mtlsDisabled_keepsTheDefaultConnector_andTheHandshakeFails() throws Exception {
        TestPki.Issued leaf = TestPki.serverLeaf(clusterCa, "hugmesh-federation-api");
        try (TlsTestServer server = federationApi(leaf, clusterCa.cert())) {
            runner(server.baseUrl()).run(ctx -> {
                FederationModuleClient client = ctx.getBean(FederationModuleClient.class);
                assertThatThrownBy(() -> client.registerModule("wiki", "Wiki", "ui", "u", "./M", "1",
                        "public", true, null).block(WAIT))
                        .hasStackTraceContaining("SSL");
            });
            assertThat(server.seen()).as("no request may reach HTTP without the handshake").isEmpty();
        }
    }

    /** Trusts ONLY the configured CA: a server whose certificate chains elsewhere is refused. */
    @Test
    void mtlsEnabled_refusesAServerCertificateFromAnotherCa() throws Exception {
        TestPki.Issued rogueCa = TestPki.ca("some other CA");
        TestPki.Issued leaf = TestPki.serverLeaf(rogueCa, "hugmesh-federation-api");
        try (TlsTestServer server = federationApi(leaf, rogueCa.cert())) {
            runner(server.baseUrl(), mtlsOn()).run(ctx -> {
                FederationModuleClient client = ctx.getBean(FederationModuleClient.class);
                assertThatThrownBy(() -> client.registerModule("wiki", "Wiki", "ui", "u", "./M", "1",
                        "public", true, null).block(WAIT))
                        .hasStackTraceContaining("SSL");
            });
            assertThat(server.seen()).isEmpty();
        }
    }
}
