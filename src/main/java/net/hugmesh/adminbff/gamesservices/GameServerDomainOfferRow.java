package net.hugmesh.adminbff.gamesservices;

import org.springframework.data.annotation.Id;
import org.springframework.data.annotation.PersistenceCreator;
import org.springframework.data.annotation.Transient;
import org.springframework.data.domain.Persistable;
import org.springframework.data.relational.core.mapping.Column;
import org.springframework.data.relational.core.mapping.Table;

import java.time.Instant;

/**
 * One row of {@code game_server_domain_offer} (Liquibase changeset 090) — the durable shape
 * for a {@link GameServerDomainOffer}. PK is an app-generated {@code varchar(36)} UUID string;
 * the entity implements {@link Persistable} so a freshly-minted row INSERTs.
 * {@link GameServerDomainOfferRepository} maps between the two.
 */
@Table("game_server_domain_offer")
public record GameServerDomainOfferRow(
        @Id @Column("id") String id,
        @Column("domain") String domain,
        @Column("slug") String slug,
        @Column("offered_by_superadmin") boolean offeredBySuperadmin,
        @Column("enabled_by_admin") boolean enabledByAdmin,
        @Column("max_instances") int maxInstances,
        @Column("created_at") Instant createdAt,
        @Column("created_by_subject") String createdBySubject,
        @Column("updated_at") Instant updatedAt,
        @Transient boolean isNew) implements Persistable<String> {

    @PersistenceCreator
    public GameServerDomainOfferRow(String id, String domain, String slug,
                                    boolean offeredBySuperadmin, boolean enabledByAdmin,
                                    int maxInstances, Instant createdAt, String createdBySubject,
                                    Instant updatedAt) {
        this(id, domain, slug, offeredBySuperadmin, enabledByAdmin, maxInstances, createdAt,
                createdBySubject, updatedAt, false);
    }

    GameServerDomainOffer toDomain() {
        return new GameServerDomainOffer(id, domain, slug, offeredBySuperadmin, enabledByAdmin,
                maxInstances, createdAt, createdBySubject, updatedAt);
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
