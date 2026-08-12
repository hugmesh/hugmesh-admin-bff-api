package net.hugmesh.adminbff.servicecatalog;

import org.springframework.data.r2dbc.repository.Modifying;
import org.springframework.data.r2dbc.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.time.Instant;

/**
 * Reactive (R2DBC) Spring Data store for {@code service_curation} (changeset 100). The offered
 * lookup, the per-domain catalog read, and the scoped/unscoped offered lists are derived
 * finders; the state-guarded CAS withdraw UPDATE is a {@code @Query} static-final constant. The
 * {@link ServiceCurationRepository} facade maps rows to/from the {@link ServiceCuration} domain
 * record.
 */
public interface ServiceCurationR2dbcRepository
        extends ReactiveCrudRepository<ServiceCurationRow, String> {

    /**
     * Insert a new OFFERED row with a DB-generated id (changelog 200): {@code id} is OMITTED →
     * filled from the {@code (gen_random_uuid())::text} column DEFAULT; {@code RETURNING id} reads
     * the generated varchar(36) back ({@code Mono<String>}). The supplied columns match the
     * {@link ServiceCurationRow} column order (id excluded).
     */
    String INSERT_RETURNING_ID = """
            INSERT INTO service_curation \
            (domain, service_key, state, curated_by_subject, created_at, updated_at) \
            VALUES (:domain, :serviceKey, :state, :curatedBySubject, :createdAt, :updatedAt) \
            RETURNING id""";

    @Query(INSERT_RETURNING_ID)
    Mono<String> insertReturningId(@Param("domain") String domain,
                                   @Param("serviceKey") String serviceKey,
                                   @Param("state") String state,
                                   @Param("curatedBySubject") String curatedBySubject,
                                   @Param("createdAt") Instant createdAt,
                                   @Param("updatedAt") Instant updatedAt);

    /** The OFFERED row for (domain, service_key), if any — the idempotency / withdraw target. */
    Mono<ServiceCurationRow> findByDomainAndServiceKeyAndState(
            String domain, String serviceKey, String state);

    /** Every curation row for a domain (offered + withdrawn), by (service_key, created_at). */
    Flux<ServiceCurationRow> findByDomainOrderByServiceKeyAscCreatedAtAsc(String domain);

    /** Offered rows for a domain, by service_key — the scoped admin catalog. */
    Flux<ServiceCurationRow> findByStateAndDomainOrderByServiceKey(String state, String domain);

    /** ALL offered rows (unscoped SUPERADMIN), domain then service_key. */
    Flux<ServiceCurationRow> findByStateOrderByDomainAscServiceKeyAsc(String state);

    /** CAS {@code offered -> withdrawn} for one id, bumping {@code updated_at}. */
    String MARK_WITHDRAWN =
            "UPDATE service_curation SET state = 'withdrawn', updated_at = now() "
            + "WHERE id = :id AND state = 'offered'";

    @Modifying
    @Query(MARK_WITHDRAWN)
    Mono<Long> markWithdrawn(String id);
}
