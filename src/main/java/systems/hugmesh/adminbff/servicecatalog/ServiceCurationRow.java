package systems.hugmesh.adminbff.servicecatalog;

import org.springframework.data.annotation.Id;
import org.springframework.data.annotation.PersistenceCreator;
import org.springframework.data.annotation.Transient;
import org.springframework.data.domain.Persistable;
import org.springframework.data.relational.core.mapping.Column;
import org.springframework.data.relational.core.mapping.Table;

import java.time.Instant;

/**
 * One row of {@code service_curation} (Liquibase changeset 100) — the durable shape for a
 * {@link ServiceCuration}. PK is an app-generated {@code varchar(36)} UUID string; the entity
 * implements {@link Persistable} so a freshly-minted row INSERTs.
 * {@link ServiceCurationRepository} maps between the two.
 */
@Table("service_curation")
public record ServiceCurationRow(
        @Id @Column("id") String id,
        @Column("domain") String domain,
        @Column("service_key") String serviceKey,
        @Column("state") String state,
        @Column("curated_by_subject") String curatedBySubject,
        @Column("created_at") Instant createdAt,
        @Column("updated_at") Instant updatedAt,
        @Transient boolean isNew) implements Persistable<String> {

    @PersistenceCreator
    public ServiceCurationRow(String id, String domain, String serviceKey, String state,
                              String curatedBySubject, Instant createdAt, Instant updatedAt) {
        this(id, domain, serviceKey, state, curatedBySubject, createdAt, updatedAt, false);
    }

    ServiceCuration toDomain() {
        return new ServiceCuration(id, domain, serviceKey, state, curatedBySubject, createdAt,
                updatedAt);
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
