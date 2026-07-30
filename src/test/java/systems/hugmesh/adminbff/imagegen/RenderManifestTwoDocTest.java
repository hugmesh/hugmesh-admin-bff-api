package systems.hugmesh.adminbff.imagegen;

import org.junit.jupiter.api.Test;
import systems.hugmesh.adminbff.sshterminal.ImageBuild;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * The FULL IMAGE_SPEC_JSON channel render (worklist redesign item 1b) — pure string assertions
 * on {@code renderManifest} (no DB, no cluster):
 * <ul>
 *   <li>spec persisted → a TWO-doc manifest: a per-build {@code ConfigMap
 *       hugmesh-image-spec-<id>} carrying {@code spec.json}, PREPENDED to the Job (so the
 *       fabric8 {@code client.load().create()} applies both in one call);</li>
 *   <li>spec {@code null} → the LEGACY single-doc 6-env manifest, unchanged, NO ConfigMap;</li>
 *   <li>{@code ${DOMAIN}} stays SERVER-derived from {@code build.domain()} — a hostile
 *       {@code cluster_domain} inside the spec never drives the Job's tenancy env;</li>
 *   <li>a spec carrying a raw newline is rejected (defence-in-depth backstop to the envelope
 *       validator, since the ConfigMap body bypasses {@code yamlSafe}).</li>
 * </ul>
 */
class RenderManifestTwoDocTest {

    // renderManifest never touches the repo, so a null repo is fine for this pure render test.
    private final ImageBuildOrchestrator orch =
            new ImageBuildOrchestrator(null, new NoopImageJobLauncher(), 64);

    private static ImageBuild build(String domain, String spec) {
        return new ImageBuild("00000000-0000-0000-0000-000000000042", null, "admin@x",
                "brandx/alice", domain, ImageBuild.IMAGE_PRIMARY, "rpi5", null,
                ImageBuild.STATUS_QUEUED, true, null, null, null, null, null, null, spec);
    }

    @Test
    void withSpec_emitsConfigMapPlusJobTwoDoc() {
        String spec = "{\"role\":\"gateway\",\"platform\":\"rpi5\",\"hostname\":\"gw\"}";
        String m = orch.renderManifest(build("brandx", spec));

        assertThat(m).contains("kind: ConfigMap")
                .contains("name: hugmesh-image-spec-00000000-0000-0000-0000-000000000042")
                .contains("spec.json: |")
                .contains(spec)
                .contains("\n---\n")
                .contains("kind: Job");
        // The ConfigMap doc precedes the Job doc.
        assertThat(m.indexOf("kind: ConfigMap")).isLessThan(m.indexOf("kind: Job"));
        // Placeholders fully substituted.
        assertThat(m).doesNotContain("${BUILD_ID}").doesNotContain("${IMAGE_TYPE}");
    }

    @Test
    void withoutSpec_emitsLegacySingleDoc_noConfigMap() {
        String m = orch.renderManifest(build("brandx", null));

        assertThat(m).contains("kind: Job")
                .doesNotContain("kind: ConfigMap")
                .doesNotContain("spec.json: |")
                .doesNotContain("${BUILD_ID}");
    }

    @Test
    void domainStaysServerDerived_notFromSpecClusterDomain() {
        // A hostile cluster_domain inside the spec must NOT drive the Job's DOMAIN env — that is
        // substituted only from build.domain() (the server-derived validated-issuer brand).
        String spec = "{\"role\":\"gateway\",\"cluster_domain\":\"evil.attacker.example\"}";
        String m = orch.renderManifest(build("brandx", spec));

        assertThat(m).contains("value: \"brandx\"");          // DOMAIN env = server-derived brand
        assertThat(m).contains("evil.attacker.example");       // present ONLY as ConfigMap content
        // The substituted DOMAIN env is never the spec's cluster_domain.
        assertThat(m).doesNotContain("value: \"evil.attacker.example\"");
    }

    @Test
    void legacyRender_leavesImageSpecJsonEnvEmpty() {
        // The LEGACY SEAM fix: the worker (build-image.sh) branches on IMAGE_SPEC_JSON being
        // NON-EMPTY and then hard-dies when the file is missing, while a missing optional
        // ConfigMap volume still mounts an EMPTY dir — so a legacy build MUST see an empty
        // IMAGE_SPEC_JSON env (BUILD_MODE=legacy), never the constant mount path.
        String m = orch.renderManifest(build("brandx", null));

        assertThat(m).contains("- { name: IMAGE_SPEC_JSON, value: \"\" }")
                .doesNotContain("${IMAGE_SPEC_PATH}")
                .doesNotContain("value: \"/image-spec/spec.json\"");
    }

    @Test
    void specRender_keepsImageSpecJsonEnvPath() {
        // A spec build points the worker at the mounted file — and a somehow-missing file
        // still fails CLOSED worker-side ([ -f ] || die), never a silent legacy fallback.
        String m = orch.renderManifest(build("brandx", "{\"role\":\"gateway\"}"));

        assertThat(m).contains("- { name: IMAGE_SPEC_JSON, value: \"/image-spec/spec.json\" }")
                .doesNotContain("${IMAGE_SPEC_PATH}");
    }

    @Test
    void specWithRawNewline_isRejected() {
        String spec = "{\"role\":\"x\"}\n        privileged: true";
        assertThatThrownBy(() -> orch.renderManifest(build("brandx", spec)))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("single-line");
    }
}
