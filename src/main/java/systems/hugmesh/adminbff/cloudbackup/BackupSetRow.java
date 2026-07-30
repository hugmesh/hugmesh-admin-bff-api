package systems.hugmesh.adminbff.cloudbackup;

import org.springframework.data.annotation.Id;
import org.springframework.data.annotation.PersistenceCreator;
import org.springframework.data.annotation.Transient;
import org.springframework.data.domain.Persistable;
import org.springframework.data.relational.core.mapping.Column;
import org.springframework.data.relational.core.mapping.Table;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * One row of {@code backup_set} (Liquibase changeset 160) — the durable shape for a
 * {@link BackupSet}. {@code scope} / {@code destination_kind} are stored as wire strings and
 * {@code services} as a portable comma-joined text (not a PG {@code text[]}). PK is an
 * app-generated {@code varchar(36)} UUID string; the entity implements {@link Persistable} so
 * a freshly-minted row INSERTs. {@link BackupSetRepository} maps between the two.
 */
@Table("backup_set")
public record BackupSetRow(
        @Id @Column("id") String id,
        @Column("set_key") String setKey,
        @Column("version") long version,
        @Column("scope") String scope,
        @Column("domain") String domain,
        @Column("created_by") String createdBy,
        @Column("services") String services,
        @Column("destination_kind") String destinationKind,
        @Column("destination_ref") String destinationRef,
        @Column("size_bytes") Long sizeBytes,
        @Column("encryption_meta") String encryptionMeta,
        @Column("status") String status,
        @Column("created_at") Instant createdAt,
        @Column("started_at") Instant startedAt,
        @Column("completed_at") Instant completedAt,
        @Transient boolean isNew) implements Persistable<String> {

    @PersistenceCreator
    public BackupSetRow(String id, String setKey, long version, String scope, String domain,
                        String createdBy, String services, String destinationKind,
                        String destinationRef, Long sizeBytes, String encryptionMeta, String status,
                        Instant createdAt, Instant startedAt, Instant completedAt) {
        this(id, setKey, version, scope, domain, createdBy, services, destinationKind,
                destinationRef, sizeBytes, encryptionMeta, status, createdAt, startedAt,
                completedAt, false);
    }

    BackupSet toDomain() {
        return new BackupSet(id, setKey, version, BackupCloudScope.from(scope), domain, createdBy,
                splitServices(services), BackupDestinationKind.from(destinationKind),
                destinationRef, sizeBytes, encryptionMeta, status, createdAt, startedAt, completedAt);
    }

    static List<String> splitServices(String joined) {
        if (joined == null || joined.isBlank()) {
            return List.of();
        }
        List<String> out = new ArrayList<>();
        for (String s : Arrays.asList(joined.split(","))) {
            if (s != null && !s.isBlank()) {
                out.add(s.trim());
            }
        }
        return List.copyOf(out);
    }

    @Override
    public String getId() {
        return id;
    }

    @Override
    public boolean isNew() {
        return isNew;
    }
}
