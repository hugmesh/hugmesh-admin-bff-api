package systems.hugmesh.adminbff.servicecatalog;

import org.springframework.data.annotation.Id;
import org.springframework.data.annotation.PersistenceCreator;
import org.springframework.data.annotation.Transient;
import org.springframework.data.domain.Persistable;
import org.springframework.data.relational.core.mapping.Column;
import org.springframework.data.relational.core.mapping.Table;

import java.time.Instant;

/**
 * One row of {@code app_profile} (Liquibase changeset 101) — the durable shape for an
 * {@link AppProfile}. PK is an app-generated {@code varchar(36)} UUID string; the entity
 * implements {@link Persistable} so a freshly-minted row INSERTs. {@link AppProfileRepository}
 * maps between the two.
 */
@Table("app_profile")
public record AppProfileRow(
        @Id @Column("id") String id,
        @Column("name") String name,
        @Column("profile_json") String profileJson,
        @Column("created_by_subject") String createdBySubject,
        @Column("created_at") Instant createdAt,
        @Column("updated_at") Instant updatedAt,
        @Transient boolean isNew) implements Persistable<String> {

    @PersistenceCreator
    public AppProfileRow(String id, String name, String profileJson, String createdBySubject,
                         Instant createdAt, Instant updatedAt) {
        this(id, name, profileJson, createdBySubject, createdAt, updatedAt, false);
    }

    AppProfile toDomain() {
        return new AppProfile(id, name, profileJson, createdBySubject, createdAt, updatedAt);
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
