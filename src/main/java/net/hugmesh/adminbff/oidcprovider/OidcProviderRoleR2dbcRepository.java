package net.hugmesh.adminbff.oidcprovider;

import org.springframework.data.r2dbc.repository.Modifying;
import org.springframework.data.r2dbc.repository.Query;
import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

/**
 * Reactive (R2DBC) Spring Data store for {@code oidc_provider_default_roles} (changeset
 * 081, COMPOSITE PK). Reads are derived finders, the delete a derived {@code deleteBy...},
 * and the idempotent insert an {@code @Query} (ON CONFLICT DO NOTHING — a dialect upsert
 * that is not derivable). The {@link OidcProviderRoleRepository} facade composes these.
 */
public interface OidcProviderRoleR2dbcRepository extends ReactiveCrudRepository<OidcProviderRole, String> {

    /** All rows for a domain, provider-then-role ordered. */
    Flux<OidcProviderRole> findByDomainOrderByProviderAscRoleNameAsc(String domain);

    /** Role names for a (domain, provider), role-ordered. */
    Flux<OidcProviderRole> findByDomainAndProviderOrderByRoleName(String domain, String provider);

    /** Remove all rows for a (domain, provider). */
    Mono<Long> deleteByDomainAndProvider(String domain, String provider);

    /** Idempotent insert of one (domain, provider, role_name) row. */
    String INSERT_IGNORE =
            "INSERT INTO oidc_provider_default_roles(domain, provider, role_name) "
            + "VALUES (:domain, :provider, :role) ON CONFLICT DO NOTHING";

    @Modifying
    @Query(INSERT_IGNORE)
    Mono<Long> insertIgnore(String domain, String provider, String role);
}
