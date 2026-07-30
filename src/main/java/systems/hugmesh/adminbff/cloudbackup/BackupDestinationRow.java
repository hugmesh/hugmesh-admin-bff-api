package systems.hugmesh.adminbff.cloudbackup;

import org.springframework.data.annotation.Id;
import org.springframework.data.annotation.PersistenceCreator;
import org.springframework.data.annotation.Transient;
import org.springframework.data.domain.Persistable;
import org.springframework.data.relational.core.mapping.Column;
import org.springframework.data.relational.core.mapping.Table;

import java.time.Instant;

/**
 * One row of {@code backup_destination} (Liquibase changeset 160) — the durable shape for a
 * {@link BackupDestination}. {@code kind} is stored as its wire string. PK is an
 * app-generated {@code varchar(36)} UUID string; the entity implements {@link Persistable} so
 * a freshly-minted row INSERTs. {@link BackupDestinationRepository} maps between the two.
 */
@Table("backup_destination")
public record BackupDestinationRow(
        @Id @Column("id") String id,
        @Column("kind") String kind,
        @Column("destination_ref") String destinationRef,
        @Column("secret_ref") String secretRef,
        @Column("domain") String domain,
        @Column("updated_by") String updatedBy,
        @Column("created_at") Instant createdAt,
        @Column("updated_at") Instant updatedAt,
        @Transient boolean isNew) implements Persistable<String> {

    @PersistenceCreator
    public BackupDestinationRow(String id, String kind, String destinationRef, String secretRef,
                                String domain, String updatedBy, Instant createdAt, Instant updatedAt) {
        this(id, kind, destinationRef, secretRef, domain, updatedBy, createdAt, updatedAt, false);
    }

    BackupDestination toDomain() {
        return new BackupDestination(id, BackupDestinationKind.from(kind), destinationRef,
                secretRef, domain, updatedBy, createdAt, updatedAt);
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
