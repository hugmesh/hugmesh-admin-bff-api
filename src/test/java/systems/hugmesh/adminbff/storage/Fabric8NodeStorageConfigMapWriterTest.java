package systems.hugmesh.adminbff.storage;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The Fabric8 writer's element JSON rendering — the load-bearing contract the generator's
 * {@code apps/13b-node-storage.yaml} list-generator consumes. Verified WITHOUT a cluster: the
 * {@code renderElementsJson} render is package-visible and total. Proves the EXACT field names
 * + an empty list -> {@code []} (the inert shape).
 */
class Fabric8NodeStorageConfigMapWriterTest {

    private final ObjectMapper mapper = new ObjectMapper();

    private Fabric8NodeStorageConfigMapWriter writer() {
        // The ClientFactory is never invoked by renderElementsJson (no cluster touched).
        return new Fabric8NodeStorageConfigMapWriter(() -> null, "devops");
    }

    @Test
    void emptyList_rendersEmptyJsonArray_inert() {
        assertThat(writer().renderElementsJson(List.of())).isEqualTo("[]");
        assertThat(writer().renderElementsJson(null)).isEqualTo("[]");
    }

    @Test
    void rendersExactElementFieldNames() throws Exception {
        StorageAssignmentElement e = new StorageAssignmentElement(
                "a-1", "owncast", "owncast-data", "pi-edge-01", "/mnt/pool-1",
                "hugmesh-backend", "4", "active");

        String json = writer().renderElementsJson(List.of(e));
        JsonNode arr = mapper.readTree(json);

        assertThat(arr.isArray()).isTrue();
        assertThat(arr).hasSize(1);
        JsonNode o = arr.get(0);
        assertThat(o.get("id").asText()).isEqualTo("a-1");
        assertThat(o.get("service").asText()).isEqualTo("owncast");
        assertThat(o.get("pvc").asText()).isEqualTo("owncast-data");
        assertThat(o.get("nodeName").asText()).isEqualTo("pi-edge-01");
        assertThat(o.get("poolPath").asText()).isEqualTo("/mnt/pool-1");
        assertThat(o.get("namespace").asText()).isEqualTo("hugmesh-backend");
        assertThat(o.get("requested").asText()).isEqualTo("4");
        assertThat(o.get("state").asText()).isEqualTo("active");
    }

    @Test
    void bytesToWholeGiCeil_roundsUp_neverZeroForPositive() {
        assertThat(StorageAssignmentElement.toWholeGiCeil(0)).isZero();
        assertThat(StorageAssignmentElement.toWholeGiCeil(1)).isEqualTo(1);
        assertThat(StorageAssignmentElement.toWholeGiCeil(StorageAssignmentElement.GIB)).isEqualTo(1);
        assertThat(StorageAssignmentElement.toWholeGiCeil(StorageAssignmentElement.GIB + 1)).isEqualTo(2);
        assertThat(StorageAssignmentElement.toWholeGiCeil(4L * StorageAssignmentElement.GIB)).isEqualTo(4);
    }
}
