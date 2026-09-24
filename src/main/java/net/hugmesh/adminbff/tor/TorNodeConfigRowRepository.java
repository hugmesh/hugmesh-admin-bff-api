package net.hugmesh.adminbff.tor;

import org.springframework.data.r2dbc.repository.Modifying;
import org.springframework.data.r2dbc.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

/**
 * Reactive (R2DBC) store for {@code tor_node_config} (changeset 360): the SUPERADMIN's
 * per-node Tor desired state.
 */
public interface TorNodeConfigRowRepository extends ReactiveCrudRepository<TorNodeConfigRow, String> {

    /**
     * Atomic INSERT-or-UPDATE of the node's managed upstream. Both arms set
     * {@code upstream_managed = true}; {@code :upstream} NULL means "the agent's built-in
     * default". {@code config_generation} starts at 1 and increments on every write, so the
     * per-node export generation strictly advances on every change the node must apply.
     */
    String UPSERT_UPSTREAM = """
            INSERT INTO tor_node_config \
            (machine_key_fp, upstream_managed, upstream, config_generation, updated_by, updated_at) \
            VALUES (:fp, true, :upstream, 1, :updatedBy, now()) \
            ON CONFLICT (machine_key_fp) DO UPDATE SET \
              upstream_managed = true, \
              upstream = EXCLUDED.upstream, \
              config_generation = tor_node_config.config_generation + 1, \
              updated_by = EXCLUDED.updated_by, \
              updated_at = now()""";

    @Modifying
    @Query(UPSERT_UPSTREAM)
    Mono<Long> upsertUpstream(@Param("fp") String fp,
                              @Param("upstream") String upstream,
                              @Param("updatedBy") String updatedBy);

    /** The config for this fingerprint, if any (UNIQUE on machine_key_fp). */
    Mono<TorNodeConfigRow> findByMachineKeyFp(String machineKeyFp);

    /** Every config row, by fingerprint. */
    Flux<TorNodeConfigRow> findByOrderByMachineKeyFpAsc();
}
