package net.hugmesh.adminbff.workload;

import org.springframework.data.r2dbc.repository.Modifying;
import org.springframework.data.r2dbc.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.time.Instant;

/**
 * Reactive (R2DBC) Spring Data store for {@code workload_console_config} (changeset 110). The
 * by-domain read and the list are derived finders; the {@code MAX(generation)} aggregate and
 * the by-domain partial UPDATE the upsert uses are {@code @Query} static-final constants. The
 * {@link WorkloadConsoleConfigRepository} facade maps rows to/from the
 * {@link WorkloadConsoleConfig} domain record and composes the read-then insert-or-update
 * upsert.
 */
public interface WorkloadConsoleConfigR2dbcRepository
        extends ReactiveCrudRepository<WorkloadConsoleConfigRow, String> {

    /**
     * Insert a fresh per-domain config row with a DB-generated id (changelog 200) — the upsert's
     * INSERT branch: {@code id} is OMITTED → filled from the {@code (gen_random_uuid())::text}
     * column DEFAULT; {@code RETURNING id} reads the generated varchar(36) back
     * ({@code Mono<String>}). Columns match the {@link WorkloadConsoleConfigRow} order (id
     * excluded). The UPDATE branch ({@link #updateByDomain}) is unchanged.
     */
    String INSERT_RETURNING_ID = """
            INSERT INTO workload_console_config \
            (domain, admin_enabled, dangerous_tier_enabled, updated_by, updated_at, generation) \
            VALUES (:domain, :adminEnabled, :dangerousTierEnabled, :updatedBy, :updatedAt, \
             :generation) \
            RETURNING id""";

    @Query(INSERT_RETURNING_ID)
    Mono<String> insertReturningId(@Param("domain") String domain,
                                   @Param("adminEnabled") boolean adminEnabled,
                                   @Param("dangerousTierEnabled") boolean dangerousTierEnabled,
                                   @Param("updatedBy") String updatedBy,
                                   @Param("updatedAt") Instant updatedAt,
                                   @Param("generation") long generation);

    /** The config row for one domain (or the GLOBAL sentinel). Empty when absent. */
    Mono<WorkloadConsoleConfigRow> findByDomain(String domain);

    /** All config rows (superadmin view), by domain. */
    Flux<WorkloadConsoleConfigRow> findByOrderByDomain();

    /** The current MAX(generation) across ALL config rows; 0 when empty. */
    String MAX_GENERATION = "SELECT COALESCE(MAX(generation), 0) FROM workload_console_config";

    @Query(MAX_GENERATION)
    Mono<Long> maxGeneration();

    /** UPDATE the existing per-domain row, bumping generation + updated_at. */
    String UPDATE_BY_DOMAIN =
            "UPDATE workload_console_config "
            + "SET admin_enabled = :ae, dangerous_tier_enabled = :dte, updated_by = :by, "
            + "    updated_at = now(), generation = :gen WHERE domain = :domain";

    @Modifying
    @Query(UPDATE_BY_DOMAIN)
    Mono<Long> updateByDomain(boolean ae, boolean dte, String by, long gen, String domain);
}
