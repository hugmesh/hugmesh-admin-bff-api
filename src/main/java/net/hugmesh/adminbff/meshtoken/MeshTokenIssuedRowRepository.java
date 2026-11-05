package net.hugmesh.adminbff.meshtoken;

import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import reactor.core.publisher.Flux;

import java.util.Collection;

/**
 * Reactive (R2DBC) store for {@code mesh_token_issued} (changeset 390). Insert ({@code save} of a
 * new {@link MeshTokenIssuedRow}) and reads only: the application role holds SELECT and INSERT
 * on this table and nothing else, so an issued-token record can never be edited or deleted.
 */
public interface MeshTokenIssuedRowRepository extends ReactiveCrudRepository<MeshTokenIssuedRow, String> {

    /** Newest first, every domain (SUPERADMIN view). */
    Flux<MeshTokenIssuedRow> findTop200ByOrderByIssuedAtDesc();

    /** Newest first, only these access domains (ADMIN view, the brand's domains). */
    Flux<MeshTokenIssuedRow> findTop200ByDomainInOrderByIssuedAtDesc(Collection<String> domains);
}
