package net.hugmesh.adminbff.imagegen;

import org.junit.jupiter.api.Test;
import org.yaml.snakeyaml.Yaml;
import net.hugmesh.adminbff.sshterminal.ImageBuild;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * Decisions 73b/73c (hugmesh-admin-bff-api#53, hugmesh-generator#368): the BFF is the source of
 * the build's stable device id and of the Vault path of its dial key, and the rendered Job carries
 * both plus a mount of the per-DEVICE Secret {@code device-ssh-<deviceId>}.
 *
 * <p>RED on origin/main 86cdf79: {@link DeviceDialIdentity} does not exist, and the rendered Job
 * carries no DEVICE_ID / VAULT_REF env and mounts {@code image-gen-dial-<buildId>}.
 */
class DeviceDialIdentityTest {

    private static final String BUILD_ID = "3F2A9B1C-4D5E-6F70-8192-A3B4C5D6E7F8";

    @Test
    void mint_isTheBuildImageShDerivation_lowercaseStripCut() {
        assertThat(DeviceDialIdentity.mintDeviceId(BUILD_ID)).isEqualTo("dev-3f2a9b1c4d5e");
        assertThat(DeviceDialIdentity.mintDeviceId("00000000-0000-0000-0000-000000000042"))
                .isEqualTo("dev-000000000000");
        // Order matters: strip AFTER lowercasing (uppercase letters survive as lowercase), cut last.
        assertThat(DeviceDialIdentity.mintDeviceId("AB_cd.EF-gh/ij klMNOPQR")).isEqualTo("dev-abcdefghijkl");
        assertThat(DeviceDialIdentity.mintDeviceId("x-1")).isEqualTo("dev-x1");
        assertThatThrownBy(() -> DeviceDialIdentity.mintDeviceId(null))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void secretName_andVaultRef_areTheGeneratorTemplateShapes() {
        assertThat(DeviceDialIdentity.secretNameFor("dev-3f2a9b1c4d5e")).isEqualTo("device-ssh-dev-3f2a9b1c4d5e");
        assertThat(DeviceDialIdentity.vaultRefFor("dev-3f2a9b1c4d5e")).isEqualTo("hugmesh/device/dev-3f2a9b1c4d5e/ssh");
    }

    /**
     * Cross-check against the REAL shell pipeline build-image.sh runs, byte for byte
     * ({@code DEVICE_ID="dev-$(printf '%s' "$BUILD_ID" | tr 'A-Z' 'a-z' | tr -cd 'a-z0-9' | cut -c1-12)"}),
     * so the two derivations cannot drift silently. Skips (never passes vacuously) without /bin/sh.
     */
    @Test
    void mint_matchesTheGeneratorShellPipeline() throws Exception {
        assumeTrue(Files.isExecutable(Path.of("/bin/sh")), "/bin/sh not available");
        for (String id : List.of(BUILD_ID, "00000000-0000-0000-0000-000000000042",
                "AB_cd.EF-gh/ij klMNOPQR", "x-1", "d1d2d3d4-e5e6-f7f8-a9b0-c1c2c3c4c5c6")) {
            ProcessBuilder pb = new ProcessBuilder("/bin/sh", "-c",
                    "printf 'dev-%s' \"$(printf '%s' \"$BUILD_ID\" | tr 'A-Z' 'a-z' | tr -cd 'a-z0-9' | cut -c1-12)\"");
            pb.environment().put("BUILD_ID", id);
            pb.environment().put("LC_ALL", "C");
            Process p = pb.start();
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            try (InputStream in = p.getInputStream()) {
                in.transferTo(out);
            }
            assertThat(p.waitFor()).isZero();
            assertThat(DeviceDialIdentity.mintDeviceId(id))
                    .as("build id %s", id)
                    .isEqualTo(out.toString(StandardCharsets.UTF_8));
        }
    }

    // ── the rendered Job (ImageBuildOrchestrator.renderManifest) ─────────────────────────────

    private final ImageBuildOrchestrator orch =
            new ImageBuildOrchestrator(null, new NoopImageJobLauncher(), 64);

    private static ImageBuild build(String id, String spec) {
        return new ImageBuild(id, null, "admin@x", "alice", "brandx",
                ImageBuild.IMAGE_PRIMARY, "rpi5", null, ImageBuild.STATUS_QUEUED, true,
                null, null, null, null, null, null, spec);
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> jobDoc(String manifest) {
        List<Map<String, Object>> docs = new ArrayList<>();
        for (Object d : new Yaml().loadAll(manifest)) {
            docs.add((Map<String, Object>) d);
        }
        return docs.stream().filter(d -> "Job".equals(d.get("kind"))).findFirst().orElseThrow();
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> podSpec(Map<String, Object> job) {
        Map<String, Object> spec = (Map<String, Object>) job.get("spec");
        Map<String, Object> template = (Map<String, Object>) spec.get("template");
        return (Map<String, Object>) template.get("spec");
    }

    @SuppressWarnings("unchecked")
    private static Map<String, String> builderEnv(Map<String, Object> job) {
        List<Map<String, Object>> containers = (List<Map<String, Object>>) podSpec(job).get("containers");
        Map<String, String> env = new java.util.LinkedHashMap<>();
        for (Map<String, Object> e : (List<Map<String, Object>>) containers.get(0).get("env")) {
            Object v = e.get("value");
            env.put((String) e.get("name"), v == null ? null : v.toString());
        }
        return env;
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> dialKeyVolume(Map<String, Object> job) {
        for (Map<String, Object> v : (List<Map<String, Object>>) podSpec(job).get("volumes")) {
            if ("dial-key".equals(v.get("name"))) {
                return (Map<String, Object>) v.get("secret");
            }
        }
        throw new AssertionError("no dial-key volume");
    }

    @Test
    void renderedJob_carriesMintedDeviceId_vaultRef_andMountsThePerDeviceSecret() {
        for (String spec : new String[] {null, "{\"platform\":\"rpi5\"}"}) {
            String m = orch.renderManifest(build(BUILD_ID, spec));
            Map<String, Object> job = jobDoc(m);
            Map<String, String> env = builderEnv(job);

            String deviceId = DeviceDialIdentity.mintDeviceId(BUILD_ID);
            assertThat(env).containsEntry("DEVICE_ID", "dev-3f2a9b1c4d5e")
                    .containsEntry("DEVICE_ID", deviceId)
                    .containsEntry("VAULT_REF", "hugmesh/device/dev-3f2a9b1c4d5e/ssh")
                    .containsEntry("VAULT_REF", DeviceDialIdentity.vaultRefFor(deviceId));
            Map<String, Object> vol = dialKeyVolume(job);
            assertThat(vol).containsEntry("secretName", "device-ssh-dev-3f2a9b1c4d5e")
                    .containsEntry("secretName", DeviceDialIdentity.secretNameFor(deviceId))
                    .containsEntry("optional", true);
            // No per-BUILD Secret anywhere, and no placeholder survives.
            assertThat(m).doesNotContain("image-gen-dial-")
                    .doesNotContain("${DEVICE_ID}").doesNotContain("${VAULT_REF}");
        }
    }
}
