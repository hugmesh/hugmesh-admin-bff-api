package systems.hugmesh.adminbff.appearance;

import org.springframework.data.annotation.Id;
import org.springframework.data.relational.core.mapping.Column;
import org.springframework.data.relational.core.mapping.Table;

import java.time.Instant;

/**
 * Persisted shape of {@code mastodon_appearance_default} (Liquibase changeset 240) —
 * the composite PK {@code (domain, pref_key)} durable row backing the admin-configured
 * platform-wide default appearance/preferences fallback for the hugmesh-mastodon-ui
 * remote's {@code PreferencesService}. Column names/types match the Liquibase changelog
 * EXACTLY.
 *
 * <p>The TRUE PK is composite; Spring Data needs a single {@code @Id} for entity
 * metadata, so {@code domain} carries it. The repo never keys CRUD-by-id — all access is
 * DERIVED finders / {@code @Query} upsert — so the marker never narrows a query.
 */
@Table("mastodon_appearance_default")
public record MastodonAppearanceDefaultEntity(
        @Id
        @Column("domain") String domain,
        @Column("pref_key") String prefKey,
        @Column("pref_value") String prefValue,
        @Column("updated_by") String updatedBy,
        @Column("updated_at") Instant updatedAt) {
}
