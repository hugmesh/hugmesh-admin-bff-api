package net.hugmesh.adminbff.storage;

import org.springframework.data.annotation.Id;
import org.springframework.data.annotation.PersistenceCreator;
import org.springframework.data.annotation.Transient;
import org.springframework.data.domain.Persistable;
import org.springframework.data.relational.core.mapping.Column;
import org.springframework.data.relational.core.mapping.Table;

import java.time.Instant;

/**
 * One row of {@code node_storage_pool} (Liquibase changeset 085) — the durable shape for a
 * {@link StoragePool}. PK is an app-generated {@code varchar(36)} UUID string; the entity
 * implements {@link Persistable} so a freshly-minted row INSERTs. {@link StoragePoolRepository}
 * maps between the two.
 */
@Table("node_storage_pool")
public record StoragePoolRow(
        @Id @Column("id") String id,
        @Column("device_id") String deviceId,
        @Column("disk_serial") String diskSerial,
        @Column("pool_path") String poolPath,
        @Column("reserved_bytes") long reservedBytes,
        @Column("is_exclusive") boolean isExclusive,
        @Column("filesystem") String filesystem,
        @Column("state") String state,
        @Column("domain") String domain,
        @Column("propagation_state") String propagationState,
        @Column("generation") long generation,
        @Column("created_by") String createdBy,
        @Column("created_at") Instant createdAt,
        @Column("detached_at") Instant detachedAt,
        @Column("detached_by") String detachedBy,
        @Transient boolean isNew) implements Persistable<String> {

    @PersistenceCreator
    public StoragePoolRow(String id, String deviceId, String diskSerial, String poolPath,
                          long reservedBytes, boolean isExclusive, String filesystem, String state,
                          String domain, String propagationState, long generation, String createdBy,
                          Instant createdAt, Instant detachedAt, String detachedBy) {
        this(id, deviceId, diskSerial, poolPath, reservedBytes, isExclusive, filesystem, state,
                domain, propagationState, generation, createdBy, createdAt, detachedAt, detachedBy,
                false);
    }

    StoragePool toDomain() {
        return new StoragePool(id, deviceId, diskSerial, poolPath, reservedBytes, isExclusive,
                filesystem, state, domain, propagationState, generation, createdBy, createdAt,
                detachedAt, detachedBy);
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
