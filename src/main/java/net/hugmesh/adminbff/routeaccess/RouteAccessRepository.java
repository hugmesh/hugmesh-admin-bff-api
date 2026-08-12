package net.hugmesh.adminbff.routeaccess;

import org.springframework.stereotype.Repository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import net.hugmesh.commons.security.PrincipalDomain;

import java.time.LocalDateTime;
import java.util.UUID;

/**
 * Reactive (R2DBC) store for gateway_route_access — the SOURCE OF TRUTH for the
 * per-gateway external-access rules (schema in Liquibase
 * {@code db/changelog/001-gateway-route-access.xml}). IDs are DB-GENERATED — the
 * {@code id} column carries a {@code gen_random_uuid()} DEFAULT (pgcrypto, changelog
 * 200), so the INSERT omits {@code id} and reads the generated UUID back via
 * {@code RETURNING id} (the app no longer mints {@code UUID.randomUUID()}).
 *
 * <p>Backed by the Spring Data {@link RouteAccessRowRepository} (no raw
 * {@code DatabaseClient}); maps the {@link RouteAccessRow} entity to the
 * {@link RouteRule} projection.
 */
@Repository
public class RouteAccessRepository {

    private final RouteAccessRowRepository repo;

    public RouteAccessRepository(RouteAccessRowRepository repo) {
        this.repo = repo;
    }

    /** All rules (every brand). UNSCOPED — used internally. */
    public Flux<RouteRule> list() {
        return repo.findAllByOrderByGatewayAscUrlPatternAsc().map(RouteAccessRow::toRule);
    }

    /**
     * Rules VISIBLE to the given tenant scope — the ADMIN read surface. A scoped admin
     * sees ONLY their brand's rules; SUPERADMIN (unscoped) sees all. Fail-closed: a null
     * scope is treated as scoped to NO_DOMAIN.
     */
    public Flux<RouteRule> list(PrincipalDomain scope) {
        if (scope == null || scope.scoped()) {
            String domain = scope == null ? PrincipalDomain.NO_DOMAIN : scope.domain();
            return repo.findByDomainOrderByGatewayAscUrlPatternAsc(domain).map(RouteAccessRow::toRule);
        }
        return list();
    }

    /** Insert a rule (DB-generated id) and return it with that id populated. The INSERT
     *  omits {@code id} (filled from the {@code gen_random_uuid()} column DEFAULT, changelog
     *  200) and {@code RETURNING id} hands back the generated UUID, which we render into the
     *  returned {@link RouteRule} (same field order/values as before). */
    public Mono<RouteRule> add(RouteRule r) {
        String domain = r.domain() == null ? PrincipalDomain.NO_DOMAIN : r.domain();
        LocalDateTime updatedAt = LocalDateTime.now();
        return repo.insertReturningId(r.gateway(), r.urlPattern(), r.role(), r.casdoorUser(),
                        r.allow(), domain, r.mfaRequired(), updatedAt)
                .map(genId -> new RouteRule(genId.toString(), r.gateway(), r.urlPattern(), r.role(),
                        r.casdoorUser(), r.allow(), domain, r.mfaRequired()));
    }

    /** UNSCOPED delete by id (internal). */
    public Mono<Void> delete(String id) {
        return repo.deleteById(UUID.fromString(id));
    }

    /**
     * Delete a rule by id WITHIN the given tenant scope. A scoped admin's DELETE only
     * affects a row that is BOTH the id AND in their brand; SUPERADMIN deletes any id.
     * Returns the rows-deleted count (0 = not in scope / absent).
     */
    public Mono<Long> delete(String id, PrincipalDomain scope) {
        UUID uuid = UUID.fromString(id);
        if (scope == null || scope.scoped()) {
            String domain = scope == null ? PrincipalDomain.NO_DOMAIN : scope.domain();
            return repo.deleteByIdAndDomain(uuid, domain);
        }
        // SUPERADMIN unscoped: delete any id, returning the rows-deleted count.
        return repo.existsById(uuid)
                .flatMap(exists -> exists
                        ? repo.deleteById(uuid).thenReturn(1L)
                        : Mono.just(0L));
    }
}
