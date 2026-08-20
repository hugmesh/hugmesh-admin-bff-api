package net.hugmesh.adminbff.egressvpn;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import io.fabric8.kubernetes.api.model.Secret;
import io.fabric8.kubernetes.client.KubernetesClient;
import io.fabric8.kubernetes.client.KubernetesClientException;
import io.fabric8.kubernetes.client.dsl.MixedOperation;
import io.fabric8.kubernetes.client.dsl.NonNamespaceOperation;
import io.fabric8.kubernetes.client.dsl.Resource;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.slf4j.LoggerFactory;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * {@link Fabric8VpnConfigSecretWriter}: the SECRET SHAPE the node-level
 * {@code hugmesh-vpn-reconcile} agent anticipates ({@code name = data key = secretRef}, so a
 * default Secret volume projection materialises exactly the {@code ${VPN_SECRET_DIR}/<secretRef>}
 * file the agent reads), the {@code Mono.usingWhen} client lifecycle (always closed, every
 * failure swallowed to {@code false} — mirrors {@code Fabric8InstanceConfigMapWriterTest}), and
 * the REDACTION contract: the config body (the private VPN key) NEVER appears in a log line, on
 * the success path OR the failure path.
 */
@SuppressWarnings("unchecked")
class Fabric8VpnConfigSecretWriterTest {

    private static final String BODY = """
            [Interface]
            PrivateKey = wg-private-key-material
            [Peer]
            PublicKey = pub
            Endpoint = 1.2.3.4:51820
            """;

    private Logger rootLogger;
    private ListAppender<ILoggingEvent> appender;

    @BeforeEach
    void captureLogs() {
        rootLogger = (Logger) LoggerFactory.getLogger(org.slf4j.Logger.ROOT_LOGGER_NAME);
        appender = new ListAppender<>();
        appender.list = new java.util.concurrent.CopyOnWriteArrayList<>();
        appender.start();
        rootLogger.addAppender(appender);
        rootLogger.setLevel(Level.TRACE);
    }

    @AfterEach
    void detach() {
        rootLogger.detachAppender(appender);
    }

    private void assertNoKeyMaterialInLogs() {
        for (ILoggingEvent e : appender.list) {
            assertThat(e.getFormattedMessage())
                    .as("no log line may carry the config body / private key")
                    .doesNotContain("wg-private-key-material")
                    .doesNotContain("[Interface]");
        }
    }

    private static Resource<Secret> stubSecretChain(KubernetesClient client, ArgumentCaptor<Secret> captor) {
        MixedOperation<Secret, ?, Resource<Secret>> secrets = mock(MixedOperation.class);
        NonNamespaceOperation<Secret, ?, Resource<Secret>> inNamespace = mock(NonNamespaceOperation.class);
        Resource<Secret> resource = mock(Resource.class);
        when(client.secrets()).thenReturn((MixedOperation) secrets);
        when(secrets.inNamespace("hugmesh-backend")).thenReturn((NonNamespaceOperation) inNamespace);
        when(inNamespace.resource(captor != null ? captor.capture() : any(Secret.class)))
                .thenReturn(resource);
        return resource;
    }

    @Test
    void successfulApply_returnsTrue_withTheAgentAnticipatedShape_andClosesTheClient() {
        KubernetesClient client = mock(KubernetesClient.class);
        ArgumentCaptor<Secret> captor = ArgumentCaptor.forClass(Secret.class);
        Resource<Secret> resource = stubSecretChain(client, captor);
        when(resource.serverSideApply()).thenReturn(new Secret());

        Fabric8VpnConfigSecretWriter writer =
                new Fabric8VpnConfigSecretWriter(() -> client, "hugmesh-backend");

        Boolean applied = writer.write("egress-vpn-brandx-proton-us", "brandx", "proton-us",
                VpnConfig.KIND_WIREGUARD, BODY).block();

        assertThat(applied).isTrue();
        verify(resource, times(1)).serverSideApply();
        verify(client, times(1)).close();

        Secret secret = captor.getValue();
        // name = data key = secretRef — the ${VPN_SECRET_DIR}/<secretRef> contract.
        assertThat(secret.getMetadata().getName()).isEqualTo("egress-vpn-brandx-proton-us");
        assertThat(secret.getMetadata().getNamespace()).isEqualTo("hugmesh-backend");
        assertThat(secret.getStringData()).containsOnlyKeys("egress-vpn-brandx-proton-us");
        assertThat(secret.getStringData().get("egress-vpn-brandx-proton-us")).isEqualTo(BODY);
        assertThat(secret.getType()).isEqualTo("Opaque");
        assertThat(secret.getMetadata().getLabels())
                .containsEntry("hugmesh.net/optional-service", "egress-vpn")
                .containsEntry("hugmesh.net/vpn-config-domain", "brandx");

        assertNoKeyMaterialInLogs();
    }

    @Test
    void clientFactoryFailure_returnsFalse_withoutThrowing_andRedacts() {
        Fabric8VpnConfigSecretWriter writer = new Fabric8VpnConfigSecretWriter(
                () -> { throw new KubernetesClientException("no cluster"); }, "hugmesh-backend");

        assertThat(writer.write("ref-1", "brandx", "proton-us",
                VpnConfig.KIND_WIREGUARD, BODY).block()).isFalse();
        assertNoKeyMaterialInLogs();
    }

    @Test
    void applyFailure_returnsFalse_andStillClosesTheClient_andRedacts() {
        KubernetesClient client = mock(KubernetesClient.class);
        Resource<Secret> resource = stubSecretChain(client, null);
        when(resource.serverSideApply()).thenThrow(new KubernetesClientException("admission denied"));

        Fabric8VpnConfigSecretWriter writer =
                new Fabric8VpnConfigSecretWriter(() -> client, "hugmesh-backend");

        assertThat(writer.write("ref-1", "brandx", "proton-us",
                VpnConfig.KIND_WIREGUARD, BODY).block()).isFalse();
        verify(client, times(1)).close();
        assertNoKeyMaterialInLogs();
    }

    @Test
    void isReal_isTrue_andConstructionTouchesNoClient() {
        Fabric8VpnConfigSecretWriter writer =
                new Fabric8VpnConfigSecretWriter(() -> {
                    throw new AssertionError("construction must not build a client");
                }, "hugmesh-backend");
        assertThat(writer.isReal()).isTrue();
    }

    @Test
    void noopWriter_dropsBytes_returnsFalse_andRedacts() {
        assertThat(new NoopVpnConfigSecretWriter().write("ref-1", "brandx", "proton-us",
                VpnConfig.KIND_WIREGUARD, BODY).block()).isFalse();
        assertNoKeyMaterialInLogs();
    }
}
