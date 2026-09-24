package net.hugmesh.adminbff.imagegen;

import java.util.Locale;

/**
 * The ONE place the per-device dial IDENTITY of an image build is derived — the stable device id,
 * the K8s Secret name the device's dial key is synced into, and the Vault path that Secret is
 * synced from. Operator decisions 73a/73b/73c of 2026-09-23 (hugmesh-admin-bff-api#53,
 * hugmesh-generator#368):
 *
 * <ul>
 *   <li><b>73a = B — admin-bff derives the Secret name.</b> The ingest body can no longer name a
 *       Secret: {@code k8s_secret_name} becomes a PATH SEGMENT under the dial key mount
 *       ({@code <key-mount-path>/<k8s_secret_name>/<key-file>}), so it is computed here, never read
 *       from the in-cluster Job's report.</li>
 *   <li><b>73b = B — the name is {@code device-ssh-<deviceId>}</b>, the per-device Secret of
 *       hugmesh-generator {@code specs/cluster/manifests/external-secrets/device-ssh-externalsecret.tpl.yaml}
 *       (keyed by the DEVICE id, not the build id). Note the device id is itself minted from the
 *       build id (see {@link #mintDeviceId}), so today every build is a new device id and a new
 *       Secret; a rebuild does NOT reuse an earlier device's Secret.</li>
 *   <li><b>73c = B — the BFF passes the Vault path to the Job</b> ({@code VAULT_REF} env) and the
 *       Job reports it back; {@code seedDial} stores it only when it equals {@link #vaultRefFor}.</li>
 * </ul>
 *
 * <p>BOTH {@link ImageBuildOrchestrator#renderManifest} (which hands {@code DEVICE_ID} /
 * {@code VAULT_REF} to the Job and mounts {@code device-ssh-<id>}) AND
 * {@code ImageBuildService.seedDial} (which checks the Job's report against them) call these
 * helpers, so the two sides cannot drift apart.
 *
 * <p><b>Where the device id comes from.</b> No registry-issued id exists when the Job is rendered —
 * {@code device_registry} rows are created later by headscale enrollment — so the id reuses
 * EXACTLY the derivation hugmesh-generator {@code docker/build-image.sh} applies today
 * ({@code DEVICE_ID="dev-$(printf '%s' "$BUILD_ID" | tr 'A-Z' 'a-z' | tr -cd 'a-z0-9' | cut -c1-12)"}):
 * lowercase, then strip everything that is not {@code [a-z0-9]}, then keep the first 12 characters.
 * For the app-generated UUID build id that is its first 12 hex digits (48 bits): a collision
 * between two builds is theoretical; if one ever happened, the second build's seed would find the
 * first build's row for that device id and skip (one dial row per device), it would not overwrite
 * it. The existing gap is unchanged: a dial row is seeded only when a {@code device_registry} row
 * with THIS id already exists.
 */
public final class DeviceDialIdentity {

    /** The prefix of the per-device dial Secret (generator ExternalSecret template). */
    public static final String SECRET_PREFIX = "device-ssh-";

    private static final String DEVICE_PREFIX = "dev-";
    private static final int DEVICE_ID_CHARS = 12;

    private DeviceDialIdentity() {
    }

    /**
     * The stable device id minted for a build: {@code dev-<first 12 of lower(buildId) with every
     * non-[a-z0-9] removed>}. Same order of operations as build-image.sh (lowercase, strip, cut).
     */
    public static String mintDeviceId(String buildId) {
        if (buildId == null) {
            throw new IllegalArgumentException("buildId is required to mint a device id");
        }
        String alnum = buildId.toLowerCase(Locale.ROOT).replaceAll("[^a-z0-9]", "");
        return DEVICE_PREFIX + alnum.substring(0, Math.min(DEVICE_ID_CHARS, alnum.length()));
    }

    /** The K8s Secret name the device's dial key is synced into: {@code device-ssh-<deviceId>}. */
    public static String secretNameFor(String deviceId) {
        return SECRET_PREFIX + deviceId;
    }

    /**
     * The Vault KV path the device's dial Secret is synced from — the {@code remoteRef.key} of the
     * generator template ({@code hugmesh/device/<deviceId>/ssh}), NOT the template header's
     * {@code secret/<brand>/...} prose.
     */
    public static String vaultRefFor(String deviceId) {
        return "hugmesh/device/" + deviceId + "/ssh";
    }
}
