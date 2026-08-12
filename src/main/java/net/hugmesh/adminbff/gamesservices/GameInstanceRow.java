package net.hugmesh.adminbff.gamesservices;

import org.springframework.data.annotation.Id;
import org.springframework.data.annotation.PersistenceCreator;
import org.springframework.data.annotation.Transient;
import org.springframework.data.domain.Persistable;
import org.springframework.data.relational.core.mapping.Column;
import org.springframework.data.relational.core.mapping.Table;

import java.time.Instant;

/**
 * One row of {@code game_instance} (Liquibase changeset 091) — the durable shape for a
 * {@link GameInstance}. PK is an app-generated {@code varchar(36)} UUID string; the entity
 * implements {@link Persistable} so a freshly-minted row INSERTs.
 * {@link GameInstanceRepository} maps between the two.
 */
@Table("game_instance")
public record GameInstanceRow(
        @Id @Column("id") String id,
        @Column("domain") String domain,
        @Column("slug") String slug,
        @Column("name") String name,
        @Column("state") String state,
        @Column("propagation_state") String propagationState,
        @Column("owner_subject") String ownerSubject,
        @Column("created_at") Instant createdAt,
        @Column("ending_at") Instant endingAt,
        @Column("namespace") String namespace,
        @Column("node_port") Integer nodePort,
        @Column("console_path") String consolePath,
        @Column("updated_at") Instant updatedAt,
        @Transient boolean isNew) implements Persistable<String> {

    @PersistenceCreator
    public GameInstanceRow(String id, String domain, String slug, String name, String state,
                           String propagationState, String ownerSubject, Instant createdAt,
                           Instant endingAt, String namespace, Integer nodePort, String consolePath,
                           Instant updatedAt) {
        this(id, domain, slug, name, state, propagationState, ownerSubject, createdAt, endingAt,
                namespace, nodePort, consolePath, updatedAt, false);
    }

    GameInstance toDomain() {
        return new GameInstance(id, domain, slug, name, state, propagationState, ownerSubject,
                createdAt, endingAt, namespace, nodePort, consolePath, updatedAt);
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
