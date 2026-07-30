package systems.hugmesh.adminbff.capability;

import org.springframework.data.r2dbc.repository.Modifying;
import org.springframework.data.r2dbc.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.time.Instant;

/**
 * Reactive (R2DBC) Spring Data store for {@code domain_capability} (changeset 303). The
 * by-(domain, capability) read, the by-domain list, and the full list are derived finders;
 * the {@code MAX(generation)} aggregate and the by-(domain, capability) partial UPDATE the
 * upsert uses are {@code @Query} static-final constants. The
 * {@link DomainCapabilityRepository} facade maps rows to/from the {@link DomainCapability}
 * domain record and composes the read-then insert-or-update upsert — CLONES
 * {@code WorkloadConsoleConfigR2dbcRepository} verbatim, keyed on the composite
 * (domain, capability) instead of domain alone.
 */
public interface DomainCapabilityR2dbcRepository
        extends ReactiveCrudRepository<DomainCapabilityRow, String> {

    /**
     * Insert a fresh (domain, capability) gate row with a DB-generated id — the upsert's
     * INSERT branch: {@code id} is OMITTED → filled from the
     * {@code (gen_random_uuid())::text} column DEFAULT; {@code RETURNING id} reads the
     * generated varchar(36) back ({@code Mono<String>}). Columns match the
     * {@link DomainCapabilityRow} order (id excluded). The UPDATE branch
     * ({@link #updateByDomainAndCapability}) is unchanged.
     */
    String INSERT_RETURNING_ID = """
            INSERT INTO domain_capability \
            (domain, capability, granted, enabled, updated_by, updated_at, generation) \
            VALUES (:domain, :capability, :granted, :enabled, :updatedBy, :updatedAt, \
             :generation) \
            RETURNING id""";

    @Query(INSERT_RETURNING_ID)
    Mono<String> insertReturningId(@Param("domain") String domain,
                                   @Param("capability") String capability,
                                   @Param("granted") boolean granted,
                                   @Param("enabled") boolean enabled,
                                   @Param("updatedBy") String updatedBy,
                                   @Param("updatedAt") Instant updatedAt,
                                   @Param("generation") long generation);

    /** The gate row for one (domain, capability) pair (or the GLOBAL sentinel). Empty
     *  when absent. */
    Mono<DomainCapabilityRow> findByDomainAndCapability(String domain, String capability);

    /** All gate rows for one domain (every capability that domain has ever touched) —
     *  the domain-scoped ADMIN read. */
    Flux<DomainCapabilityRow> findByDomainOrderByCapability(String domain);

    /** All gate rows (superadmin view), by domain then capability. */
    Flux<DomainCapabilityRow> findByOrderByDomainAscCapabilityAsc();

    /** The current MAX(generation) across ALL gate rows; 0 when empty. */
    String MAX_GENERATION = "SELECT COALESCE(MAX(generation), 0) FROM domain_capability";

    @Query(MAX_GENERATION)
    Mono<Long> maxGeneration();

    /** UPDATE the existing (domain, capability) row, bumping generation + updated_at. */
    String UPDATE_BY_DOMAIN_AND_CAPABILITY =
            "UPDATE domain_capability "
            + "SET granted = :granted, enabled = :enabled, updated_by = :by, "
            + "    updated_at = now(), generation = :gen "
            + "WHERE domain = :domain AND capability = :capability";

    @Modifying
    @Query(UPDATE_BY_DOMAIN_AND_CAPABILITY)
    Mono<Long> updateByDomainAndCapability(boolean granted, boolean enabled, String by, long gen,
                                           String domain, String capability);
}
