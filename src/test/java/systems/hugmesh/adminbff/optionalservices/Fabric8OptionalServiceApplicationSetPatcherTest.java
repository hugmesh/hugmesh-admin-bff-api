package systems.hugmesh.adminbff.optionalservices;

import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The load-bearing pure transform {@link Fabric8OptionalServiceApplicationSetPatcher#applyDesiredToElements}
 * — the offline KEYSTONE contract the whole runtime toggle hinges on. Verified WITHOUT a
 * cluster: the transform is package-visible + total. Proves it flips ONLY {@code installed}
 * (by slug), preserves every other field + order, leaves unknown-slug elements untouched,
 * and keeps edge-ai distinct from edge-ai-analysis/edge-ai-tts. The fixture mirrors
 * {@code apps/13a-optional-services.yaml}'s element shape.
 */
class Fabric8OptionalServiceApplicationSetPatcherTest {

    /** An element as fabric8 reads it from 13a: an ordered map with a String installed. */
    private static Map<String, Object> el(String slug, String path, String ns, String installed) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("slug", slug);
        m.put("path", path);
        m.put("namespace", ns);
        m.put("installed", installed);
        return m;
    }

    /** A 4-element fixture spanning the pre-cut-over all-"false" baseline. */
    private static List<Map<String, Object>> fixture() {
        List<Map<String, Object>> e = new ArrayList<>();
        e.add(el("akkoma", "specs/cluster/manifests/akkoma", "hugmesh-backend", "false"));
        e.add(el("edge-ai", "specs/cluster/manifests/edge-ai", "hugmesh-inference", "false"));
        e.add(el("edge-ai-analysis", "specs/cluster/manifests/edge-ai-analysis", "hugmesh-inference", "false"));
        e.add(el("edge-ai-tts", "specs/cluster/manifests/edge-ai-tts", "hugmesh-inference", "false"));
        return e;
    }

    private static Map<String, Object> bySlug(List<Map<String, Object>> els, String slug) {
        return els.stream().filter(m -> slug.equals(m.get("slug"))).findFirst().orElseThrow();
    }

    @Test
    void nullOrEmptyDesired_returnsFaithfulCopy_noFlips() {
        List<Map<String, Object>> in = fixture();
        assertThat(Fabric8OptionalServiceApplicationSetPatcher.applyDesiredToElements(in, null)).isEqualTo(in);
        assertThat(Fabric8OptionalServiceApplicationSetPatcher.applyDesiredToElements(in, Map.of())).isEqualTo(in);
        // null elements -> empty list (inert), never NPE.
        assertThat(Fabric8OptionalServiceApplicationSetPatcher.applyDesiredToElements(null, Map.of("akkoma", true)))
                .isEmpty();
    }

    @Test
    void flipsOnlyInstalled_bySlug_preservesOtherFieldsAndOrder() {
        Map<String, Boolean> desired = new LinkedHashMap<>();
        desired.put("akkoma", true);
        desired.put("edge-ai", true);
        desired.put("edge-ai-analysis", false);
        desired.put("edge-ai-tts", false);

        List<Map<String, Object>> out =
                Fabric8OptionalServiceApplicationSetPatcher.applyDesiredToElements(fixture(), desired);

        // order preserved
        assertThat(out).extracting(m -> m.get("slug"))
                .containsExactly("akkoma", "edge-ai", "edge-ai-analysis", "edge-ai-tts");
        // installed flipped exactly per desired; edge-ai != edge-ai-analysis/edge-ai-tts
        assertThat(bySlug(out, "akkoma").get("installed")).isEqualTo("true");
        assertThat(bySlug(out, "edge-ai").get("installed")).isEqualTo("true");
        assertThat(bySlug(out, "edge-ai-analysis").get("installed")).isEqualTo("false");
        assertThat(bySlug(out, "edge-ai-tts").get("installed")).isEqualTo("false");
        // other fields untouched
        assertThat(bySlug(out, "akkoma").get("path")).isEqualTo("specs/cluster/manifests/akkoma");
        assertThat(bySlug(out, "akkoma").get("namespace")).isEqualTo("hugmesh-backend");
    }

    @Test
    void doesNotMutateInput() {
        List<Map<String, Object>> in = fixture();
        Fabric8OptionalServiceApplicationSetPatcher.applyDesiredToElements(in, Map.of("akkoma", true));
        assertThat(bySlug(in, "akkoma").get("installed")).isEqualTo("false"); // input still baseline
    }

    @Test
    void elementWithSlugAbsentFromDesired_isUntouched() {
        // desired only mentions akkoma -> the three edge-ai elements keep their baseline.
        List<Map<String, Object>> out =
                Fabric8OptionalServiceApplicationSetPatcher.applyDesiredToElements(fixture(), Map.of("akkoma", true));
        assertThat(bySlug(out, "akkoma").get("installed")).isEqualTo("true");
        assertThat(bySlug(out, "edge-ai").get("installed")).isEqualTo("false");
        assertThat(bySlug(out, "edge-ai-analysis").get("installed")).isEqualTo("false");
    }
}
