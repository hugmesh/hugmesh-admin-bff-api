package net.hugmesh.adminbff.cloudbackup;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * A single {@code backup_set} row — one backup REQUEST / job (schema in Liquibase
 * {@code db/changelog/160-cloud-backups.xml}).
 *
 * <p>VERSIONED: a backup's history is the chain of sets sharing the same {@code setKey} (the
 * logical backup identity); each run is a fresh row with an incremented {@code version}, so
 * the version-history endpoint lists the chain and a restore targets one row {@code id} within
 * it. The version is allocated MAX(version)+1 within a {@code (domain, setKey)} by the service
 * (the device-license {@code maxGeneration} idiom).
 *
 * <ul>
 *   <li>{@code scope} — {@code DOMAIN} (a brand admin's own brand) or {@code TOTAL}
 *       (superadmin-only, the whole cloud).</li>
 *   <li>{@code domain} — the brand the set belongs to: the VALIDATED-ISSUER brand for a DOMAIN
 *       set, the superadmin's home domain for a TOTAL set. Stamped, never client-supplied; the
 *       scoped-admin read predicate.</li>
 *   <li>{@code createdBy} — the JWT SUBJECT that requested the backup (owner == subject,
 *       fail-closed).</li>
 *   <li>{@code services} — the selected running services (the per-service backup menu).</li>
 *   <li>{@code destinationKind}/{@code destinationRef} — the destination chosen for this run,
 *       denormalised from {@code backup_destination} at request time so the run is
 *       reproducible.</li>
 *   <li>{@code encryptionMeta} — the AES repo / age-recipient REFERENCE only (a JSON object
 *       {@code {repo,recipientRef,algo}}). NEVER the key bytes.</li>
 *   <li>{@code status} — {@code pending} / {@code running} / {@code complete} / {@code
 *       failed}.</li>
 * </ul>
 */
public record BackupSet(
        String id,
        String setKey,
        long version,
        BackupCloudScope scope,
        String domain,
        String createdBy,
        List<String> services,
        BackupDestinationKind destinationKind,
        String destinationRef,
        Long sizeBytes,
        String encryptionMeta,
        String status,
        Instant createdAt,
        Instant startedAt,
        Instant completedAt) {

    public BackupSet {
        services = services == null ? null : Collections.unmodifiableList(new ArrayList<>(services));
    }

    public static final String STATUS_PENDING = "pending";
    public static final String STATUS_RUNNING = "running";
    public static final String STATUS_COMPLETE = "complete";
    public static final String STATUS_FAILED = "failed";

    public boolean isTotal() {
        return scope != null && scope.isTotal();
    }
}
