package systems.hugmesh.adminbff.device;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for {@link HeadscaleNodesClient#parse(String)} — the load-bearing, live-binary-free
 * bit: which JSON field the canonical fingerprint comes from ({@code fp-field}, machineKey vs
 * nodeKey), the empty-fp skip (a node we cannot key is never a candidate), and the array vs
 * {@code {"nodes":[…]}} envelope tolerance. The actual {@code headscale} CLI is NEVER invoked
 * here (mocked at the JSON layer), per the verify contract.
 */
class HeadscaleNodesClientTest {

    private final ObjectMapper mapper = new ObjectMapper();

    private HeadscaleNodesClient client(String fpField) {
        RegistryHeadscaleProperties p = new RegistryHeadscaleProperties();
        p.setEnabled(true);
        p.setFpField(fpField);
        return new HeadscaleNodesClient(p, mapper);
    }

    @Test
    void parse_usesConfiguredFpField_nodeKeyDefault() {
        // The default fp-field is the design's best guess matching provision.sh's baked
        // .Self.PublicKey == nodeKey. With fp-field=nodeKey the nodeKey value is the fp.
        String json = "[{\"machineKey\":\"mkey:AAA\",\"nodeKey\":\"nodekey:BBB\","
                + "\"givenName\":\"node-1\",\"user\":{\"name\":\"brandx\"},"
                + "\"forcedTags\":[\"tag:mesh_1\"]}]";
        List<HeadscaleNode> nodes = client(RegistryHeadscaleProperties.DEFAULT_FP_FIELD).parse(json);
        assertThat(nodes).hasSize(1);
        assertThat(nodes.get(0).machineKeyFp()).isEqualTo("nodekey:BBB");
        assertThat(nodes.get(0).hostname()).isEqualTo("node-1");
        assertThat(nodes.get(0).user()).isEqualTo("brandx");
        assertThat(nodes.get(0).meshId()).isEqualTo("tag:mesh_1");
    }

    @Test
    void parse_fpFieldMachineKey_picksMachineKey() {
        // If a live control node confirms machineKey is canonical, flipping the config flips
        // which field the opaque fp is read from — NO code change. This proves the parameter.
        String json = "[{\"machineKey\":\"mkey:AAA\",\"nodeKey\":\"nodekey:BBB\",\"givenName\":\"n\"}]";
        List<HeadscaleNode> nodes = client("machineKey").parse(json);
        assertThat(nodes).hasSize(1);
        assertThat(nodes.get(0).machineKeyFp()).isEqualTo("mkey:AAA");
    }

    @Test
    void parse_skipsNodeWithNoFingerprintInAnyField() {
        // A node with no value in the configured field NOR the known fallbacks is skipped —
        // a node we cannot key is never a registrable candidate (fail-closed, never blank fp).
        String json = "[{\"givenName\":\"unkeyable\"},"
                + "{\"nodeKey\":\"nodekey:OK\",\"givenName\":\"keyable\"}]";
        List<HeadscaleNode> nodes = client("nodeKey").parse(json);
        assertThat(nodes).hasSize(1);
        assertThat(nodes.get(0).machineKeyFp()).isEqualTo("nodekey:OK");
    }

    @Test
    void parse_tolerantOfNodesEnvelope() {
        String json = "{\"nodes\":[{\"nodeKey\":\"nodekey:X\",\"name\":\"n\"}]}";
        List<HeadscaleNode> nodes = client("nodeKey").parse(json);
        assertThat(nodes).hasSize(1);
        assertThat(nodes.get(0).machineKeyFp()).isEqualTo("nodekey:X");
    }

    @Test
    void parse_garbageJson_isEmptyNotError() {
        assertThat(client("nodeKey").parse("not json at all")).isEmpty();
        assertThat(client("nodeKey").parse("")).isEmpty();
    }
}
