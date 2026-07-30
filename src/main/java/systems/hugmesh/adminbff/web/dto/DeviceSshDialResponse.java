package systems.hugmesh.adminbff.web.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import systems.hugmesh.adminbff.sshterminal.DeviceSshDial;

/**
 * The NON-SECRET projection of a {@code device_ssh_dial} row for the SUPERADMIN dial-management UI.
 * Returns ONLY status / generation / pins / pointers — NEVER private key material (the private dial
 * key lives in Vault, referenced by {@code vaultRef}; only the REFERENCE is surfaced, never bytes).
 * A record so springdoc surfaces it typed.
 *
 * @param deviceId      the device this dial material is for
 * @param dialUser      the SSH user the BFF dials the node as
 * @param hostKeyFp     the pinned device host-key fingerprint (the value the dial compares; pin only)
 * @param dialPubFp     the fingerprint of the BFF's dial PUBLIC key (non-secret; private key in Vault)
 * @param vaultRef      the POINTER to the private dial key in Vault (a reference path, never bytes)
 * @param k8sSecretName the K8s Secret name ESO syncs the private key into (a name, never bytes)
 * @param status        PENDING / ACTIVE / REVOKED
 * @param generation    the monotonic rotation/lifecycle counter
 */
@Schema(name = "DeviceSshDialResponse",
        description = "Non-secret device dial row (status/generation/pins/pointers) — never key bytes.")
public record DeviceSshDialResponse(
        String deviceId,
        String dialUser,
        @Schema(description = "Pinned device host-key fingerprint (pin only).") String hostKeyFp,
        @Schema(description = "Fingerprint of the BFF dial PUBLIC key (private key lives in Vault).")
        String dialPubFp,
        @Schema(description = "Vault POINTER to the private dial key (a reference, never key bytes).")
        String vaultRef,
        @Schema(description = "K8s Secret NAME the private key is synced into (a name, never bytes).")
        String k8sSecretName,
        @Schema(description = "PENDING / ACTIVE / REVOKED.") String status,
        long generation) {

    /** Project a row to its non-secret response (the private key is never in the row to begin with). */
    public static DeviceSshDialResponse of(DeviceSshDial d) {
        return new DeviceSshDialResponse(d.deviceId(), d.dialUser(), d.hostKeyFp(), d.dialPubFp(),
                d.vaultRef(), d.k8sSecretName(), d.status(), d.generation());
    }
}
