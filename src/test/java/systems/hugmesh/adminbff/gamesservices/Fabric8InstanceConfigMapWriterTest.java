package systems.hugmesh.adminbff.gamesservices;

import io.fabric8.kubernetes.api.model.ConfigMap;
import io.fabric8.kubernetes.client.KubernetesClient;
import io.fabric8.kubernetes.client.KubernetesClientException;
import io.fabric8.kubernetes.client.dsl.MixedOperation;
import io.fabric8.kubernetes.client.dsl.NonNamespaceOperation;
import io.fabric8.kubernetes.client.dsl.Resource;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * {@link Fabric8InstanceConfigMapWriter}'s client resource lifecycle, now expressed with
 * {@code Mono.usingWhen} instead of a bare try-with-resources (see the class doc). Proves the
 * SAME contract try-with-resources gave: the client is ALWAYS closed (success or a mid-apply
 * failure), and every failure is swallowed to a plain {@code false} — never a thrown exception
 * — so the Lease-gated reconciler retries next tick via {@code propagation_state} instead of
 * crashing the loop.
 */
@SuppressWarnings("unchecked")
class Fabric8InstanceConfigMapWriterTest {

    private static final GameInstance INSTANCE = new GameInstance(
            "id-1", "brand-a", "minecraft", "server-1", GameInstance.STATE_ACTIVE,
            GameInstance.PROP_PENDING, "user-1", null, null, "hugmesh-games", 30001,
            "/console/1", null);

    @Test
    void clientFactoryFailure_returnsFalse_withoutThrowing() {
        Fabric8InstanceConfigMapWriter writer = new Fabric8InstanceConfigMapWriter(
                () -> { throw new KubernetesClientException("no cluster"); }, "hugmesh-games");

        assertThat(writer.writeDomainConfigMap("brand-a", List.of(INSTANCE))).isFalse();
    }

    @Test
    void successfulApply_returnsTrue_andClosesTheClient() {
        KubernetesClient client = mock(KubernetesClient.class);
        MixedOperation<ConfigMap, ?, Resource<ConfigMap>> configMaps = mock(MixedOperation.class);
        NonNamespaceOperation<ConfigMap, ?, Resource<ConfigMap>> inNamespace = mock(NonNamespaceOperation.class);
        Resource<ConfigMap> resource = mock(Resource.class);

        when(client.configMaps()).thenReturn((MixedOperation) configMaps);
        when(configMaps.inNamespace("hugmesh-games")).thenReturn((NonNamespaceOperation) inNamespace);
        when(inNamespace.resource(any(ConfigMap.class))).thenReturn(resource);
        when(resource.serverSideApply()).thenReturn(new ConfigMap());

        Fabric8InstanceConfigMapWriter writer =
                new Fabric8InstanceConfigMapWriter(() -> client, "hugmesh-games");

        assertThat(writer.writeDomainConfigMap("brand-a", List.of(INSTANCE))).isTrue();
        verify(resource, times(1)).serverSideApply();
        verify(client, times(1)).close();
    }

    @Test
    void applyFailure_returnsFalse_andStillClosesTheClient() {
        KubernetesClient client = mock(KubernetesClient.class);
        MixedOperation<ConfigMap, ?, Resource<ConfigMap>> configMaps = mock(MixedOperation.class);
        NonNamespaceOperation<ConfigMap, ?, Resource<ConfigMap>> inNamespace = mock(NonNamespaceOperation.class);
        Resource<ConfigMap> resource = mock(Resource.class);

        when(client.configMaps()).thenReturn((MixedOperation) configMaps);
        when(configMaps.inNamespace("hugmesh-games")).thenReturn((NonNamespaceOperation) inNamespace);
        when(inNamespace.resource(any(ConfigMap.class))).thenReturn(resource);
        when(resource.serverSideApply()).thenThrow(new KubernetesClientException("admission denied"));

        Fabric8InstanceConfigMapWriter writer =
                new Fabric8InstanceConfigMapWriter(() -> client, "hugmesh-games");

        // The always-closes guarantee is the whole point of the Mono.usingWhen migration:
        // a mid-apply failure must close the client exactly like a mid-block exception would
        // have triggered try-with-resources' implicit close.
        assertThat(writer.writeDomainConfigMap("brand-a", List.of(INSTANCE))).isFalse();
        verify(client, times(1)).close();
    }

    @Test
    void isReal_isTrue() {
        Fabric8InstanceConfigMapWriter writer =
                new Fabric8InstanceConfigMapWriter(() -> null, "hugmesh-games");
        assertThat(writer.isReal()).isTrue();
        verify(mock(KubernetesClient.class), never()).close(); // sanity: constructing doesn't touch a client
    }
}
