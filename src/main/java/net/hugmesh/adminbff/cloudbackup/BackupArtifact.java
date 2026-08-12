package net.hugmesh.adminbff.cloudbackup;

import java.time.Instant;

/**
 * A single {@code backup_artifact} row — the per-SERVICE record under a {@link BackupSet}
 * (one per selected running service). The set's overall {@code status} aggregates these.
 *
 * <ul>
 *   <li>{@code setId} — the parent {@link BackupSet} id (FK).</li>
 *   <li>{@code service} — the running service this artifact captures (a service key from the
 *       per-service backup menu).</li>
 *   <li>{@code kind} — {@code db_dump} (pg_dump), {@code pv_snapshot} (Velero PV snapshot), or
 *       {@code config} (ConfigMap/manifest).</li>
 *   <li>{@code status} — {@code pending} / {@code running} / {@code complete} / {@code
 *       failed}.</li>
 * </ul>
 */
public record BackupArtifact(
        String id,
        String setId,
        String service,
        String kind,
        Long sizeBytes,
        String status,
        Instant createdAt,
        Instant completedAt) {

    public static final String KIND_DB_DUMP = "db_dump";
    public static final String KIND_PV_SNAPSHOT = "pv_snapshot";
    public static final String KIND_CONFIG = "config";

    public static final String STATUS_PENDING = "pending";
    public static final String STATUS_RUNNING = "running";
    public static final String STATUS_COMPLETE = "complete";
    public static final String STATUS_FAILED = "failed";
}
