package systems.hugmesh.adminbff.sshissue;

import java.time.Instant;

/**
 * A single {@code admin_ssh_issued_key} row — the issuance AUDIT record for admin SSH
 * key-ISSUANCE (SSH PR-4, Option B; schema in Liquibase
 * {@code db/changelog/172-admin-ssh-issued-key.xml}). One row per Ed25519 keypair the BFF
 * MINTS for an {@code operator} to SSH into a licensed {@code device}.
 *
 * <p>This is NOT the enforcement record — SSH authorization lives in the 011
 * {@code device_ssh_license} registry (the node matches the offered key's SHA256 {@code %f}
 * against {@code key_fingerprints} and re-emits it). "Issuing a key" puts this credential's
 * {@link #fingerprint} into a DEVICE-scoped license row ({@link #licenseId} the backing row);
 * this table records WHO issued WHICH credential, WHEN, with what NON-SECRET public material,
 * and its lifecycle, so the admin UI can list + revoke and tie each one back to its license.
 *
 * <p><b>NO PRIVATE KEY.</b> There is no private-key field (or column). The minted private key
 * is held only in a short-TTL leader-pinned single-use in-memory store, streamed ONCE on
 * download, then dropped — never persisted, never logged. {@link #publicKey} is the NON-SECRET
 * issued OpenSSH public line; {@link #fingerprint} is its {@code SHA256:...} form (the same
 * {@code %f} the node computes from the offered key and the license pins).
 *
 * <ul>
 *   <li>{@code state} — {@code issued} (live: fingerprint is in the backing license) /
 *       {@code revoked} (CAS, audited: fingerprint removed from the backing license).</li>
 *   <li>{@code domain} — home/tenant discriminator for the ADMIN read view; stamped from the
 *       TARGET device's residency, NEVER caller-supplied.</li>
 *   <li>{@code downloadedAt} — when the single-use private key was streamed; NULL until then.</li>
 * </ul>
 */
public record AdminSshIssuedKey(
        String id,
        String deviceId,
        String licenseId,
        String operator,
        String keyType,
        String publicKey,
        String fingerprint,
        String issuedBy,
        Instant issuedAt,
        Instant downloadedAt,
        String state,
        String domain,
        Instant revokedAt,
        String revokedBy) {

    public static final String KEY_TYPE_ED25519 = "ssh-ed25519";

    public static final String STATE_ISSUED = "issued";
    public static final String STATE_REVOKED = "revoked";

    public boolean isIssued() {
        return STATE_ISSUED.equals(state);
    }

    public boolean isDownloaded() {
        return downloadedAt != null;
    }
}
