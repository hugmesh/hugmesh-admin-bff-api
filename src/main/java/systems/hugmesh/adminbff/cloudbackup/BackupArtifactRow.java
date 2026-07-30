package systems.hugmesh.adminbff.cloudbackup;

import org.springframework.data.annotation.Id;
import org.springframework.data.annotation.PersistenceCreator;
import org.springframework.data.annotation.Transient;
import org.springframework.data.domain.Persistable;
import org.springframework.data.relational.core.mapping.Column;
import org.springframework.data.relational.core.mapping.Table;

import java.time.Instant;

/**
 * One row of {@code backup_artifact} (Liquibase changeset 160, band 162) — the durable shape
 * for a {@link BackupArtifact}. PK is an app-generated {@code varchar(36)} UUID string; the
 * entity implements {@link Persistable} so a freshly-minted row INSERTs.
 * {@link BackupArtifactRepository} maps between the two.
 */
@Table("backup_artifact")
public record BackupArtifactRow(
        @Id @Column("id") String id,
        @Column("set_id") String setId,
        @Column("service") String service,
        @Column("kind") String kind,
        @Column("size_bytes") Long sizeBytes,
        @Column("status") String status,
        @Column("created_at") Instant createdAt,
        @Column("completed_at") Instant completedAt,
        @Transient boolean isNew) implements Persistable<String> {

    @PersistenceCreator
    public BackupArtifactRow(String id, String setId, String service, String kind, Long sizeBytes,
                             String status, Instant createdAt, Instant completedAt) {
        this(id, setId, service, kind, sizeBytes, status, createdAt, completedAt, false);
    }

    BackupArtifact toDomain() {
        return new BackupArtifact(id, setId, service, kind, sizeBytes, status, createdAt, completedAt);
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
