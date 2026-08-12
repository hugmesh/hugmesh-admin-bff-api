package net.hugmesh.adminbff.cloudbackup;

/**
 * Where an encrypted backup repository is written — a closed enum so a bad destination kind is
 * a clean 400 and the {@code backup_destination.kind} / {@code backup_set.destination_kind}
 * CHECK vocabulary stays in lockstep with the code.
 *
 * <ul>
 *   <li>{@link #OBJECT_STORE} — an S3 / MinIO-compatible object store (the kopia/restic AES
 *       repo lives here). {@code destinationRef} is the bucket / endpoint; {@code secretRef}
 *       points at the credentials Secret (ESO / Vault) — never the credential bytes.</li>
 *   <li>{@link #NODE_STORAGE} — the SUPERADMIN device-attached FDE volume: a
 *       {@code node_storage_pool} (schema 085) on a superadmin-owned node. {@code
 *       destinationRef} is the pool id. No {@code secretRef} (the FDE volume is unlocked at
 *       the node, not via this DB).</li>
 * </ul>
 */
public enum BackupDestinationKind {
    OBJECT_STORE("object_store"),
    NODE_STORAGE("node_storage");

    private final String wire;

    BackupDestinationKind(String wire) {
        this.wire = wire;
    }

    /** The lowercase wire name persisted in the {@code kind} / {@code destination_kind}
     *  columns (matches the CHECK vocabulary). */
    public String wire() {
        return wire;
    }

    /** Parse a wire name (case-insensitive, hyphen/underscore tolerant), or {@code null}. */
    public static BackupDestinationKind from(String s) {
        if (s == null) return null;
        String norm = s.trim().toLowerCase().replace('-', '_');
        for (BackupDestinationKind k : values()) {
            if (k.wire.equals(norm) || k.name().toLowerCase().equals(norm)) return k;
        }
        return null;
    }
}
