package net.hugmesh.adminbff.iso;

import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import reactor.core.publisher.Flux;

import java.util.UUID;

/**
 * Reactive (R2DBC) Spring Data store for {@code iso_artifacts} (changeset 002). The
 * {@link IsoRepository} facade maps the rows to the {@link IsoArtifact} projection.
 */
public interface IsoArtifactRowRepository extends ReactiveCrudRepository<IsoArtifactRow, UUID> {

    /** Every artifact, newest first ({@code ORDER BY created_at DESC}). */
    Flux<IsoArtifactRow> findAllByOrderByCreatedAtDesc();
}
