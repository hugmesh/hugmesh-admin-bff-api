package net.hugmesh.adminbff.sshterminal;

import java.time.Instant;

/**
 * A single {@code device_ssh_dial} row — the per-device dial-key REGISTRY pointer backing
 * the in-UI SSH terminal's REAL dial (schema in Liquibase
 * {@code db/changelog/170-device-ssh-keys.xml}). One row per device.
 *
 * <p>This record stores ONLY NON-SECRET material — the platform rule the device-license
 * registry (011) and cloud-backups (160) follow. The PRIVATE dial key NEVER lands here; it
 * rides Vault ({@code vaultRef}) into a K8s Secret ({@code k8sSecretName}) that the dial
 * factory (a LATER PR) reads. Nothing reads or writes this row at runtime yet — this leg
 * SHIPS DARK.
 *
 * <ul>
 *   <li>{@code deviceId} — the {@code device_registry} node this dial material is for
 *       (UNIQUE; FK ON DELETE CASCADE).</li>
 *   <li>{@code dialUser} — the SSH user the BFF dials the node as.</li>
 *   <li>{@code hostKeyPub} — the device's PUBLIC host key, used to PIN the node identity on
 *       connect (TOFU rejected). {@code hostKeyFp} is its fingerprint.</li>
 *   <li>{@code dialPubFp} — the fingerprint of the BFF's dial PUBLIC key seeded into the
 *       node's {@code authorized_keys} at build time (the matching private key is in
 *       Vault).</li>
 *   <li>{@code vaultRef} — POINTER to the private dial key in Vault (never the bytes);
 *       {@code k8sSecretName} — the Secret ESO syncs it into.</li>
 *   <li>{@code seededByBuildId} — the {@code image_build} that seeded this material
 *       (provenance), if any.</li>
 *   <li>{@code status} — {@code PENDING} / {@code ACTIVE} / {@code REVOKED}
 *       (CHECK-constrained). Starts {@code PENDING}.</li>
 *   <li>{@code generation} — monotonic rotation counter (bumped on each rotate).</li>
 * </ul>
 */
public record DeviceSshDial(
        String id,
        String deviceId,
        String dialUser,
        String hostKeyPub,
        String hostKeyFp,
        String dialPubFp,
        String vaultRef,
        String k8sSecretName,
        String seededByBuildId,
        String status,
        long generation,
        Instant createdAt,
        Instant rotatedAt) {

    public static final String STATUS_PENDING = "PENDING";
    public static final String STATUS_ACTIVE = "ACTIVE";
    public static final String STATUS_REVOKED = "REVOKED";

    /** True iff this dial material is live (the only state a real dial may use). */
    public boolean isActive() {
        return STATUS_ACTIVE.equals(status);
    }
}
