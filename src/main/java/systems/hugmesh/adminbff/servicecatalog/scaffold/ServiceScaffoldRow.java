package systems.hugmesh.adminbff.servicecatalog.scaffold;

import org.springframework.data.annotation.Id;
import org.springframework.data.annotation.PersistenceCreator;
import org.springframework.data.annotation.Transient;
import org.springframework.data.domain.Persistable;
import org.springframework.data.relational.core.mapping.Column;
import org.springframework.data.relational.core.mapping.Table;

import java.time.Instant;

/**
 * One row of {@code service_scaffold} (Liquibase changeset 320) — the durable shape for a
 * {@link ServiceScaffold}. PK is a DB-generated {@code varchar(36)} UUID string (the
 * {@code (gen_random_uuid())::text} column DEFAULT, the 100/102 App-Store convention); the entity
 * implements {@link Persistable} only for symmetry with the other App-Store rows — writes go
 * through the {@code INSERT ... RETURNING id} query, so {@link #isNew()} is never consulted on the
 * create path. {@link ServiceScaffoldRepository} maps between the two.
 */
@Table("service_scaffold")
public record ServiceScaffoldRow(
        @Id @Column("id") String id,
        @Column("domain") String domain,
        @Column("service_key") String serviceKey,
        @Column("archetype") String archetype,
        @Column("display_name") String displayName,
        @Column("mount_at") String mountAt,
        @Column("requires_role") String requiresRole,
        @Column("state") String state,
        @Column("created_by_subject") String createdBySubject,
        @Column("created_at") Instant createdAt,
        @Column("updated_at") Instant updatedAt,
        @Transient boolean isNew) implements Persistable<String> {

    @PersistenceCreator
    public ServiceScaffoldRow(String id, String domain, String serviceKey, String archetype,
                              String displayName, String mountAt, String requiresRole, String state,
                              String createdBySubject, Instant createdAt, Instant updatedAt) {
        this(id, domain, serviceKey, archetype, displayName, mountAt, requiresRole, state,
                createdBySubject, createdAt, updatedAt, false);
    }

    ServiceScaffold toDomain() {
        return new ServiceScaffold(id, domain, serviceKey, archetype, displayName, mountAt,
                requiresRole, state, createdBySubject, createdAt, updatedAt);
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
