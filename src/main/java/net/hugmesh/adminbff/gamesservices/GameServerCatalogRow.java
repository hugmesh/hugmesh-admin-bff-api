package net.hugmesh.adminbff.gamesservices;

import org.springframework.data.annotation.Id;
import org.springframework.data.annotation.PersistenceCreator;
import org.springframework.data.annotation.Transient;
import org.springframework.data.domain.Persistable;
import org.springframework.data.relational.core.mapping.Column;
import org.springframework.data.relational.core.mapping.Table;

import java.time.Instant;

/**
 * One row of {@code game_server_catalog} (Liquibase changeset 090) — the durable shape for a
 * {@link GameServerCatalogEntry}. PK is an app-generated {@code varchar(36)} UUID string; the
 * entity implements {@link Persistable} so a freshly-minted row INSERTs.
 * {@link GameServerCatalogRepository} maps between the two.
 */
@Table("game_server_catalog")
public record GameServerCatalogRow(
        @Id @Column("id") String id,
        @Column("slug") String slug,
        @Column("display_name") String displayName,
        @Column("image_ref") String imageRef,
        @Column("license_spdx") String licenseSpdx,
        @Column("protocol") String protocol,
        @Column("container_port") int containerPort,
        @Column("console_port") Integer consolePort,
        @Column("summary") String summary,
        @Column("enabled") boolean enabled,
        @Column("created_at") Instant createdAt,
        @Column("created_by_subject") String createdBySubject,
        @Column("updated_at") Instant updatedAt,
        @Transient boolean isNew) implements Persistable<String> {

    @PersistenceCreator
    public GameServerCatalogRow(String id, String slug, String displayName, String imageRef,
                                String licenseSpdx, String protocol, int containerPort,
                                Integer consolePort, String summary, boolean enabled,
                                Instant createdAt, String createdBySubject, Instant updatedAt) {
        this(id, slug, displayName, imageRef, licenseSpdx, protocol, containerPort, consolePort,
                summary, enabled, createdAt, createdBySubject, updatedAt, false);
    }

    GameServerCatalogEntry toDomain() {
        return new GameServerCatalogEntry(id, slug, displayName, imageRef, licenseSpdx, protocol,
                containerPort, consolePort, summary, enabled, createdAt, createdBySubject, updatedAt);
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
