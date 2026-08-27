package net.hugmesh.adminbff.optionalservices;

import org.junit.jupiter.api.Test;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The installed-services ConfigMap merge-patch render — the greying/capability boolean
 * contract. Verified WITHOUT a cluster: {@link Fabric8InstalledServicesConfigMapWriter#computeDataPatch}
 * is package-visible + total. Proves the patch carries EXACTLY the managed slugs (so
 * services.json / workloadConsole can never be written), with values from the desired map.
 */
class Fabric8InstalledServicesConfigMapWriterTest {

    // The 12 controller-owned slugs (== OptionalServiceRegistry.slugs() == CRD enum).
    private static final List<String> MANAGED = new OptionalServiceRegistry().slugs();

    private Fabric8InstalledServicesConfigMapWriter writer() {
        // The ClientFactory is never invoked by computeDataPatch (no cluster touched).
        return new Fabric8InstalledServicesConfigMapWriter(() -> null, "hugmesh-policy", MANAGED);
    }

    @Test
    void patchCarriesExactlyTheManagedSlugs_noUnmanagedKeys() {
        Map<String, String> patch = writer().computeDataPatch(Map.of());
        assertThat(patch.keySet()).containsExactlyElementsOf(MANAGED);
        assertThat(patch).doesNotContainKey("services.json");
        // No magic count here any more. The managed set's SIZE is not a fact this test can know:
        // it is pinned against the CRD spec.slug enum + the seed CRs by
        // OptionalServiceRegistryParityTest, and the literal 12 that used to sit here went stale
        // the moment character-forge was (correctly) added. What matters HERE is the write's
        // SHAPE: every not-toggleable slug stays out, and the slug this writer used to omit is in.
        assertThat(patch.keySet())
                .as("character-forge must now be written (it was a silently inert toggle)")
                .contains("character-forge");
        assertThat(patch.keySet())
                .as("no platform-known-but-unactionable slug may be written")
                .doesNotContainAnyElementsOf(new OptionalServiceRegistry().notToggleable().keySet());
    }

    @Test
    void nullOrEmptyDesired_rendersAllFalse() {
        assertThat(writer().computeDataPatch(null).values()).containsOnly("false");
        assertThat(writer().computeDataPatch(Map.of()).values()).containsOnly("false");
    }

    @Test
    void valuesReflectDesired_asStrings() {
        Map<String, Boolean> desired = new LinkedHashMap<>();
        desired.put("akkoma", true);
        desired.put("tuwunel", true);
        desired.put("phpbb", true);
        desired.put("games", false);
        desired.put("edge-ai", true);

        Map<String, String> patch = writer().computeDataPatch(desired);
        assertThat(patch.get("akkoma")).isEqualTo("true");
        assertThat(patch.get("tuwunel")).isEqualTo("true");
        assertThat(patch.get("phpbb")).isEqualTo("true");
        assertThat(patch.get("games")).isEqualTo("false");
        assertThat(patch.get("edge-ai")).isEqualTo("true");
        // a managed slug absent from desired defaults to "false"
        assertThat(patch.get("coturn")).isEqualTo("false");
        assertThat(patch.get("edge-ai-analysis")).isEqualTo("false");
    }
}
