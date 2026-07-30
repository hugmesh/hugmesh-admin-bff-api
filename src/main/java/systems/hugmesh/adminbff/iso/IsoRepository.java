package systems.hugmesh.adminbff.iso;

import org.springframework.stereotype.Repository;
import reactor.core.publisher.Flux;

/**
 * Lists the latest delivered ISO artifacts (reactive, R2DBC). The GitLab/ArgoCD
 * CI pipeline INSERTs a row per published ISO into iso_artifacts (Liquibase
 * {@code db/changelog/002-iso-artifacts.xml}); the admin UI renders these as
 * download links. Newest first.
 *
 * <p>Backed by the Spring Data {@link IsoArtifactRowRepository} (no raw
 * {@code DatabaseClient}); maps each row to the {@link IsoArtifact} projection.
 */
@Repository
public class IsoRepository {

    private final IsoArtifactRowRepository repo;

    public IsoRepository(IsoArtifactRowRepository repo) {
        this.repo = repo;
    }

    public Flux<IsoArtifact> list() {
        return repo.findAllByOrderByCreatedAtDesc()
                .map(r -> new IsoArtifact(r.name(), r.url()));
    }
}
