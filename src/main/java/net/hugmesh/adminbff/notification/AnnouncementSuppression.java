package net.hugmesh.adminbff.notification;

import org.springframework.data.annotation.Id;
import org.springframework.data.annotation.Transient;
import org.springframework.data.domain.Persistable;
import org.springframework.data.relational.core.mapping.Column;
import org.springframework.data.relational.core.mapping.Table;

import java.time.Instant;

/**
 * One row of {@code announcement_suppressed} (Liquibase changeset 062) — the minimal
 * per-domain ADMIN kill-switch for the {@code @system} BROADCAST channel. One row per
 * domain ({@code domain} is the natural-key PK); absence of a row = NOT suppressed.
 *
 * <p>Spring Data R2DBC entity. The PK is the natural key {@code domain} (assigned, not
 * generated), so the entity implements {@link Persistable} to control INSERT vs UPDATE
 * for the upsert (the facade picks isNew from a prior existence check).
 */
@Table("announcement_suppressed")
public record AnnouncementSuppression(
        @Id @Column("domain") String domain,
        @Column("suppressed") boolean suppressed,
        @Column("updated_by") String updatedBy,
        @Column("updated_at") Instant updatedAt,
        @Transient boolean isNew) implements Persistable<String> {

    @org.springframework.data.annotation.PersistenceCreator
    public AnnouncementSuppression(String domain, boolean suppressed, String updatedBy, Instant updatedAt) {
        this(domain, suppressed, updatedBy, updatedAt, false);
    }

    public static AnnouncementSuppression of(String domain, boolean suppressed, String updatedBy, boolean isNew) {
        return new AnnouncementSuppression(domain, suppressed, updatedBy, Instant.now(), isNew);
    }

    @Override
    public String getId() {
        return domain;
    }

    @Override
    public boolean isNew() {
        return isNew;
    }
}
