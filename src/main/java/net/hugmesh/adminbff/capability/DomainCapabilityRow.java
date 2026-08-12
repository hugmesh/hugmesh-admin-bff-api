package net.hugmesh.adminbff.capability;

import org.springframework.data.annotation.Id;
import org.springframework.data.annotation.PersistenceCreator;
import org.springframework.data.annotation.Transient;
import org.springframework.data.domain.Persistable;
import org.springframework.data.relational.core.mapping.Column;
import org.springframework.data.relational.core.mapping.Table;

import java.time.Instant;

/**
 * One row of {@code domain_capability} (Liquibase changeset 303) — the durable shape for
 * a {@link DomainCapability}. PK is a {@code varchar(36)} UUID string (DB-generated,
 * changelog-200 idiom — inline {@code (gen_random_uuid())::text} DEFAULT on the column,
 * same as {@code node_radio_device} / changeset 300); the entity implements
 * {@link Persistable} so a freshly-minted row INSERTs. {@link DomainCapabilityRepository}
 * maps between the two.
 */
@Table("domain_capability")
public record DomainCapabilityRow(
        @Id @Column("id") String id,
        @Column("domain") String domain,
        @Column("capability") String capability,
        @Column("granted") boolean granted,
        @Column("enabled") boolean enabled,
        @Column("updated_by") String updatedBy,
        @Column("updated_at") Instant updatedAt,
        @Column("generation") long generation,
        @Transient boolean isNew) implements Persistable<String> {

    @PersistenceCreator
    public DomainCapabilityRow(String id, String domain, String capability, boolean granted,
                               boolean enabled, String updatedBy, Instant updatedAt, long generation) {
        this(id, domain, capability, granted, enabled, updatedBy, updatedAt, generation, false);
    }

    DomainCapability toDomain() {
        return new DomainCapability(id, domain, capability, granted, enabled, updatedBy,
                updatedAt, generation);
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
