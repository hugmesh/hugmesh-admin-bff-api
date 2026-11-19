package net.hugmesh.adminbff.tor;

import org.springframework.data.r2dbc.repository.Modifying;
import org.springframework.data.r2dbc.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import reactor.core.publisher.Mono;

/**
 * Reactive (R2DBC) store for {@code tor_onion_rotation} (changeset 420).
 */
public interface TorRotationRowRepository extends ReactiveCrudRepository<TorRotationRow, String> {

    /**
     * Atomic INSERT-or-INCREMENT of a domain's request count: 1 on the first request, then
     * one more on every request. It never goes down.
     */
    String INCREMENT = """
            INSERT INTO tor_onion_rotation (domain, rotation_count, requested_by, requested_at) \
            VALUES (:domain, 1, :requestedBy, now()) \
            ON CONFLICT (domain) DO UPDATE SET \
              rotation_count = tor_onion_rotation.rotation_count + 1, \
              requested_by = EXCLUDED.requested_by, \
              requested_at = now()""";

    @Modifying
    @Query(INCREMENT)
    Mono<Long> increment(@Param("domain") String domain, @Param("requestedBy") String requestedBy);
}
