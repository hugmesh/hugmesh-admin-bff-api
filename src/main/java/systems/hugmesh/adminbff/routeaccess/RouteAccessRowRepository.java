package systems.hugmesh.adminbff.routeaccess;

import org.springframework.data.r2dbc.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.time.LocalDateTime;
import java.util.UUID;

/**
 * Reactive (R2DBC) Spring Data store for {@code gateway_route_access} (changeset 001 +
 * 010). Derived finders reproduce the gateway/url-pattern-ordered list (all + per-domain)
 * and the scoped/unscoped delete-by-id. The {@link RouteAccessRepository} facade maps
 * rows to/from the {@link RouteRule} projection.
 *
 * <p>DB-GENERATED UUID PK (changelog 200): the {@code id} is NO LONGER minted in Java.
 * The {@code gateway_route_access.id} column carries a {@code DEFAULT gen_random_uuid()}
 * (pgcrypto), so the INSERT OMITS {@code id} and appends {@code RETURNING id} to read the
 * database-generated UUID back. The INSERT is therefore an explicit {@code @Query} (the
 * deterministic, mod-bff-proven path) returning {@code Mono<UUID>} rather than a
 * {@code save()} with an assigned id.
 */
public interface RouteAccessRowRepository extends ReactiveCrudRepository<RouteAccessRow, UUID> {

    /** All rules, gateway-then-url-pattern ordered ({@code ORDER BY gateway, url_pattern}). */
    Flux<RouteAccessRow> findAllByOrderByGatewayAscUrlPatternAsc();

    /** Rules for one brand, gateway-then-url-pattern ordered. */
    Flux<RouteAccessRow> findByDomainOrderByGatewayAscUrlPatternAsc(String domain);

    /** Scoped delete: by id AND domain (returns rows deleted; 0 = absent / out of scope). */
    Mono<Long> deleteByIdAndDomain(UUID id, String domain);

    /**
     * Insert a rule with a DB-generated id. The {@code id} is OMITTED so Postgres fills it
     * from the {@code gen_random_uuid()} column DEFAULT (changelog 200); {@code RETURNING
     * id} reads the generated UUID back. A plain (non-{@code @Modifying}) {@code @Query}
     * returning the new id. Static-final SQL constant per the data-access standard.
     */
    String INSERT_RETURNING_ID = """
            INSERT INTO gateway_route_access \
            (gateway, url_pattern, role, casdoor_user, allow, domain, mfa_required, updated_at) \
            VALUES (:gateway, :url_pattern, :role, :casdoor_user, :allow, :domain, :mfa_required, :updated_at) \
            RETURNING id""";

    @Query(INSERT_RETURNING_ID)
    Mono<UUID> insertReturningId(@Param("gateway") String gateway,
                                 @Param("url_pattern") String urlPattern,
                                 @Param("role") String role,
                                 @Param("casdoor_user") String casdoorUser,
                                 @Param("allow") boolean allow,
                                 @Param("domain") String domain,
                                 @Param("mfa_required") boolean mfaRequired,
                                 @Param("updated_at") LocalDateTime updatedAt);
}
