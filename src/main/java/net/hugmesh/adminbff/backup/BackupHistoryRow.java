package net.hugmesh.adminbff.backup;

import org.springframework.data.annotation.Id;
import org.springframework.data.annotation.Transient;
import org.springframework.data.domain.Persistable;
import org.springframework.data.relational.core.mapping.Column;
import org.springframework.data.relational.core.mapping.Table;

import java.time.Instant;
import java.util.UUID;

/**
 * One row of {@code backup_history} (Liquibase changeset 050) — the durable storage
 * shape for a {@link BackupRecord}. PK is a {@code uuid}; {@link BackupRecord} stays the
 * JSON-serialised projection (string id, {@code @JsonProperty} names, hidden verifier
 * columns), and {@link BackupRepository} maps between the two. Implements {@link
 * Persistable} so a freshly-minted (assigned-UUID) row INSERTs.
 */
@Table("backup_history")
public record BackupHistoryRow(
        @Id @Column("id") UUID id,
        @Column("created_at") Instant createdAt,
        @Column("requested_by") String requestedBy,
        @Column("scope") String scope,
        @Column("target") String target,
        @Column("encrypted") boolean encrypted,
        @Column("status") String status,
        @Column("size_bytes") Long sizeBytes,
        @Column("error") String error,
        @Column("location_ref") String locationRef,
        @Column("verifier_salt") String verifierSalt,
        @Column("verifier") String verifier,
        @Transient boolean isNew) implements Persistable<UUID> {

    @org.springframework.data.annotation.PersistenceCreator
    public BackupHistoryRow(UUID id, Instant createdAt, String requestedBy, String scope, String target,
                            boolean encrypted, String status, Long sizeBytes, String error,
                            String locationRef, String verifierSalt, String verifier) {
        this(id, createdAt, requestedBy, scope, target, encrypted, status, sizeBytes, error,
                locationRef, verifierSalt, verifier, false);
    }

    BackupRecord toRecord() {
        return new BackupRecord(id.toString(), createdAt, requestedBy, scope, target, encrypted,
                status, sizeBytes, error, locationRef, verifierSalt, verifier);
    }

    @Override
    public UUID getId() {
        return id;
    }

    @Override
    public boolean isNew() {
        return isNew;
    }
}
