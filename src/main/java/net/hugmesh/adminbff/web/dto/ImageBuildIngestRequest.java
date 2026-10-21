package net.hugmesh.adminbff.web.dto;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import org.jspecify.annotations.Nullable;

/**
 * Body the IN-CLUSTER image-gen Job POSTs to {@code POST /bff/internal/image-builds/{id}/ingest}
 * to report build completion + the seeded NON-SECRET device/dial material.
 *
 * <p><b>NO-SECRET CONTRACT (load-bearing).</b> This DTO has NO field for a private key, and the
 * service NEVER reads or persists one. The private dial key lives ONLY in Vault and reaches the
 * device via an ESO-synced k8s Secret; it is never sent to the BFF, never logged, never
 * persisted. Everything here is non-secret REGISTRY material:
 * <ul>
 *   <li>{@code status} — {@code COMPLETED} / {@code FAILED} / {@code ERROR} (terminal only).</li>
 *   <li>{@code imageRef} / {@code keysRef} — volume-relative POINTERS to the built artifacts in
 *       the build-artifacts folder (never bytes). {@code keysRef} points at the PUBLIC keys
 *       bundle, never a private key.</li>
 *   <li>{@code deviceId} / {@code machineKeyFp} / {@code hostname} — the seeded device_registry
 *       identity (public).</li>
 *   <li>{@code dialUser} — the SSH user the BFF will dial as.</li>
 *   <li>{@code hostKeyPub} / {@code hostKeyFp} — the device's PUBLIC host key + its fingerprint
 *       (used to PIN node identity; public material).</li>
 *   <li>{@code dialPubFp} — the FINGERPRINT of the dial PUBLIC key seeded into the node's
 *       authorized_keys (public).</li>
 *   <li>{@code vaultRef} — the POINTER to where the private key lives in Vault (never the bytes).
 *       Decision 73c = B: the BFF passes it to the Job as {@code VAULT_REF} and the Job echoes it
 *       back here; the service stores it only when it equals the value the BFF minted for the
 *       build ({@code DeviceDialIdentity.vaultRefFor}).</li>
 *   <li>{@code message} / {@code error} — human-readable status text.</li>
 * </ul>
 *
 * <p><b>No Secret name (decision 73a = B, hugmesh-admin-bff-api#53).</b> The body can no longer
 * name a K8s Secret: {@code device_ssh_dial.k8s_secret_name} is a path segment under the dial key
 * mount, so the service derives it ({@code device-ssh-<deviceId>}) and there is no field for it. A
 * body that still carries {@code k8sSecretName} is ACCEPTED and the value is IGNORED (explicitly,
 * below, so a later global {@code FAIL_ON_UNKNOWN_PROPERTIES} cannot turn it into a 400):
 * hugmesh-generator {@code docker/build-image.sh} sends {@code "k8sSecretName": null} in every
 * terminal report until its own #368 change lands, and a 400 on the TERMINAL ingest would leave
 * every real build's row stuck RUNNING. Ignoring it is safe because nothing reads it.
 */
@JsonIgnoreProperties({"k8sSecretName"})
public record ImageBuildIngestRequest(

        @NotBlank(message = "status is required")
        @Pattern(regexp = "COMPLETED|FAILED|ERROR",
                message = "status must be COMPLETED, FAILED or ERROR")
        String status,

        @Size(max = 512) @Nullable String imageRef,
        @Size(max = 512) @Nullable String keysRef,

        // ── seeded device_registry identity (public) ──
        @Size(max = 36)  @Nullable String deviceId,
        @Size(max = 200) @Nullable String machineKeyFp,
        @Size(max = 253) @Nullable String hostname,

        // ── seeded device_ssh_dial NON-SECRET material ──
        @Size(max = 64)   @Nullable String dialUser,
        @Size(max = 4096) @Nullable String hostKeyPub,
        @Size(max = 200)  @Nullable String hostKeyFp,
        @Size(max = 200)  @Nullable String dialPubFp,
        @Size(max = 512)  @Nullable String vaultRef,

        @Size(max = 1024) @Nullable String message,
        @Size(max = 1024) @Nullable String error) {

    public boolean isCompleted() {
        return "COMPLETED".equals(status);
    }
}
