package net.hugmesh.adminbff.desktop;

import org.springframework.data.annotation.Id;
import org.springframework.data.annotation.PersistenceCreator;
import org.springframework.data.annotation.Transient;
import org.springframework.data.domain.Persistable;
import org.springframework.data.relational.core.mapping.Column;
import org.springframework.data.relational.core.mapping.Table;

import java.time.Instant;

/**
 * One row of {@code desktop_app_catalog} (Liquibase changeset 140) — the durable shape for a
 * {@link DesktopAppCatalogEntry}. PK is an app-generated {@code varchar(36)} UUID string; the
 * entity implements {@link Persistable} so a freshly-minted row INSERTs.
 * {@link DesktopAppCatalogRepository} maps between the two.
 */
@Table("desktop_app_catalog")
public record DesktopAppCatalogRow(
        @Id @Column("id") String id,
        @Column("app_ref") String appRef,
        @Column("display_name") String displayName,
        @Column("source") String source,
        @Column("enabled") boolean enabled,
        @Column("added_by") String addedBy,
        @Column("domain") String domain,
        @Column("created_at") Instant createdAt,
        @Column("updated_at") Instant updatedAt,
        @Transient boolean isNew) implements Persistable<String> {

    @PersistenceCreator
    public DesktopAppCatalogRow(String id, String appRef, String displayName, String source,
                                boolean enabled, String addedBy, String domain, Instant createdAt,
                                Instant updatedAt) {
        this(id, appRef, displayName, source, enabled, addedBy, domain, createdAt, updatedAt, false);
    }

    DesktopAppCatalogEntry toDomain() {
        return new DesktopAppCatalogEntry(id, appRef, displayName, source, enabled, addedBy, domain,
                createdAt, updatedAt);
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
