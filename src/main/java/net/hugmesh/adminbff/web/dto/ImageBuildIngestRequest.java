package net.hugmesh.adminbff.web.dto;

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
 *   <li>{@code vaultRef} / {@code k8sSecretName} — POINTERS to where the private key lives in
 *       Vault / which Secret ESO syncs it into (never the bytes).</li>
 *   <li>{@code message} / {@code error} — human-readable status text.</li>
 * </ul>
 */
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
        @Size(max = 253)  @Nullable String k8sSecretName,

        @Size(max = 1024) @Nullable String message,
        @Size(max = 1024) @Nullable String error) {

    public boolean isCompleted() {
        return "COMPLETED".equals(status);
    }
}
