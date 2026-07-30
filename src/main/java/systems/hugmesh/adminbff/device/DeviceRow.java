package systems.hugmesh.adminbff.device;

import org.springframework.data.annotation.Id;
import org.springframework.data.annotation.Transient;
import org.springframework.data.domain.Persistable;
import org.springframework.data.relational.core.mapping.Column;
import org.springframework.data.relational.core.mapping.Table;

import java.time.Instant;

/**
 * One row of {@code device_registry} (Liquibase changeset 011) — the durable shape for a
 * {@link Device}. PK is a {@code varchar(36)} app-generated UUID string;
 * {@code machine_key_fp} is UNIQUE. Implements {@link Persistable} so a new registration
 * INSERTs. {@link Device} stays the domain record; {@link DeviceRegistryRepository} maps
 * between the two.
 */
@Table("device_registry")
public record DeviceRow(
        @Id @Column("id") String id,
        @Column("machine_key_fp") String machineKeyFp,
        @Column("hostname") String hostname,
        @Column("tailnet_id") String tailnetId,
        @Column("image_type") String imageType,
        @Column("hardware_class") String hardwareClass,
        @Column("owner_type") String ownerType,
        @Column("physical_owner") String physicalOwner,
        @Column("domain") String domain,
        @Column("mesh_id") String meshId,
        @Column("created_at") Instant createdAt,
        @Column("last_seen_at") Instant lastSeenAt,
        @Transient boolean isNew) implements Persistable<String> {

    @org.springframework.data.annotation.PersistenceCreator
    public DeviceRow(String id, String machineKeyFp, String hostname, String tailnetId, String imageType,
                     String hardwareClass, String ownerType, String physicalOwner, String domain,
                     String meshId, Instant createdAt, Instant lastSeenAt) {
        this(id, machineKeyFp, hostname, tailnetId, imageType, hardwareClass, ownerType, physicalOwner,
                domain, meshId, createdAt, lastSeenAt, false);
    }

    Device toDomain() {
        return new Device(id, machineKeyFp, hostname, tailnetId, imageType, hardwareClass,
                ownerType, physicalOwner, domain, meshId, createdAt, lastSeenAt);
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
