package net.hugmesh.adminbff.oidcprovider;

import org.jspecify.annotations.NonNull;
import org.springframework.stereotype.Repository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

/**
 * Reactive R2DBC store for {@code oidc_provider_default_roles}.
 *
 * <p>Backed by the Spring Data {@link OidcProviderRoleR2dbcRepository} (no raw
 * {@code DatabaseClient}); composite-PK table so reads are derived finders, the
 * replace/clear use a derived delete + the idempotent ON-CONFLICT insert.
 */
@Repository
public class OidcProviderRoleRepository {

    private final OidcProviderRoleR2dbcRepository repo;

    public OidcProviderRoleRepository(OidcProviderRoleR2dbcRepository repo) {
        this.repo = repo;
    }

    /** All provider-role rows for the given domain. */
    public Flux<OidcProviderRole> listByDomain(@NonNull String domain) {
        return repo.findByDomainOrderByProviderAscRoleNameAsc(domain);
    }

    /**
     * Replace the role set for a provider in one domain with {@code roleNames}.
     * Deletes all existing rows for (domain, provider) then bulk-inserts the new set.
     */
    public Mono<Void> replaceRoles(@NonNull String domain, @NonNull String provider, Iterable<String> roleNames) {
        return repo.deleteByDomainAndProvider(domain, provider)
                .thenMany(Flux.fromIterable(roleNames)
                        .flatMap(role -> repo.insertIgnore(domain, provider, role)))
                .then();
    }

    /** Remove all roles for a provider in a domain. */
    public Mono<Void> clearRoles(@NonNull String domain, @NonNull String provider) {
        return repo.deleteByDomainAndProvider(domain, provider).then();
    }

    /**
     * List role names for a specific provider in a domain. Used by the registration flow
     * to determine which roles to assign to a newly-registered user.
     */
    public Flux<String> rolesFor(@NonNull String domain, @NonNull String provider) {
        return repo.findByDomainAndProviderOrderByRoleName(domain, provider)
                .map(OidcProviderRole::roleName);
    }
}
