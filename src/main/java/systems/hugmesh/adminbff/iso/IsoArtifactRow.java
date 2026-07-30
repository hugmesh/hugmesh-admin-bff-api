package systems.hugmesh.adminbff.iso;

import org.springframework.data.annotation.Id;
import org.springframework.data.relational.core.mapping.Column;
import org.springframework.data.relational.core.mapping.Table;

import java.time.LocalDateTime;
import java.util.UUID;

/**
 * One row of {@code iso_artifacts} (Liquibase changeset 002) — a published ISO the
 * CI pipeline INSERTed. The admin UI renders {@code name} + {@code url} as a download
 * link; {@link IsoArtifact} is that read-side projection. PK is a {@code uuid}.
 */
@Table("iso_artifacts")
public record IsoArtifactRow(
        @Id @Column("id") UUID id,
        @Column("name") String name,
        @Column("url") String url,
        @Column("created_at") LocalDateTime createdAt) {
}
