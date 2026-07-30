package systems.hugmesh.adminbff.gamesservices;

import org.springframework.data.r2dbc.repository.Modifying;
import org.springframework.data.r2dbc.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.time.Instant;

/**
 * Reactive (R2DBC) Spring Data store for {@code game_server_domain_offer} (changeset 090). The
 * scoped/unscoped lists, the per-domain list, and the (domain, slug) lookup are derived
 * finders; the (domain, slug) partial UPDATE (immutable id/domain/slug/created_*; bumps
 * {@code updated_at}) is a {@code @Query} static-final constant. The
 * {@link GameServerDomainOfferRepository} facade maps rows to/from the
 * {@link GameServerDomainOffer} domain record.
 *
 * <p>DB-GENERATED PK (changelog 200): the varchar(36) {@code id} carries a
 * {@code (gen_random_uuid())::text} DEFAULT; the INSERT OMITS {@code id} and appends
 * {@code RETURNING id} to read the database-generated string back ({@code Mono<String>}).
 * A duplicate {@code (domain, slug)} still surfaces the UNIQUE-violation (no ON CONFLICT)
 * — the race backstop the service maps to a 409.
 */
public interface GameServerDomainOfferR2dbcRepository
        extends ReactiveCrudRepository<GameServerDomainOfferRow, String> {

    /**
     * Insert a new offer with a DB-generated id (id OMITTED → filled from the column DEFAULT;
     * {@code RETURNING id} reads the generated varchar(36) back). The supplied columns match
     * the {@link GameServerDomainOfferRow} column order (id excluded).
     */
    String INSERT_RETURNING_ID = """
            INSERT INTO game_server_domain_offer \
            (domain, slug, offered_by_superadmin, enabled_by_admin, max_instances, \
             created_at, created_by_subject, updated_at) \
            VALUES (:domain, :slug, :offered_by_superadmin, :enabled_by_admin, \
             :max_instances, :created_at, :created_by_subject, :updated_at) \
            RETURNING id""";

    @Query(INSERT_RETURNING_ID)
    Mono<String> insertReturningId(@Param("domain") String domain,
                                   @Param("slug") String slug,
                                   @Param("offered_by_superadmin") boolean offeredBySuperadmin,
                                   @Param("enabled_by_admin") boolean enabledByAdmin,
                                   @Param("max_instances") int maxInstances,
                                   @Param("created_at") Instant createdAt,
                                   @Param("created_by_subject") String createdBySubject,
                                   @Param("updated_at") Instant updatedAt);

    /** Offers for a brand, by slug — the scoped admin read. */
    Flux<GameServerDomainOfferRow> findByDomainOrderBySlug(String domain);

    /** ALL offers (unscoped SUPERADMIN), domain then slug. */
    Flux<GameServerDomainOfferRow> findByOrderByDomainAscSlugAsc();

    /** The single offer for a (domain, slug), if any. */
    Mono<GameServerDomainOfferRow> findByDomainAndSlug(String domain, String slug);

    /** Update the MUTABLE flags/quota of the offer matched by (domain, slug). */
    String UPDATE_BY_DOMAIN_SLUG =
            "UPDATE game_server_domain_offer SET "
            + "offered_by_superadmin = :offered, enabled_by_admin = :enabled, "
            + "max_instances = :max, updated_at = now() "
            + "WHERE domain = :domain AND slug = :slug";

    @Modifying
    @Query(UPDATE_BY_DOMAIN_SLUG)
    Mono<Long> updateByDomainAndSlug(String domain, String slug, boolean offered, boolean enabled,
                                     int max);
}
