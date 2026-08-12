package net.hugmesh.adminbff.routeaccess;

import org.springframework.stereotype.Service;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import net.hugmesh.commons.security.PrincipalDomain;

/**
 * Route-access CRUD (reactive). Postgres is the source of truth; after each write
 * we mirror (best-effort) into the Cassandra table the gateways poll, so a rule
 * change propagates without waiting for the gateways' own Postgres refresh.
 *
 * <p>The admin surface is DOMAIN-SCOPED: a brand-scoped admin lists/adds/deletes only
 * THEIR brand's rules (the row {@code domain} is stamped on write from the validated
 * issuer and matched on read/delete); SUPERADMIN is unscoped (sees + mutates all).
 */
@Service
public class RouteAccessService {

    private final RouteAccessRepository repo;
    private final RouteMirror mirror;

    public RouteAccessService(RouteAccessRepository repo, RouteMirror mirror) {
        this.repo = repo;
        this.mirror = mirror;
    }

    /** List rules visible to {@code scope} (scoped admin = own brand; SUPERADMIN = all). */
    public Flux<RouteRule> list(PrincipalDomain scope) {
        return repo.list(scope);
    }

    public Mono<RouteRule> add(RouteRule rule) {
        // Authoritative Postgres write first (the rule already carries the acting
        // principal's domain), THEN best-effort mirror, returning the persisted row.
        return repo.add(rule)
                .flatMap(saved -> mirror.upsert(saved).thenReturn(saved));
    }

    /**
     * Delete the rule {@code id} WITHIN {@code scope}, then return the scope's
     * remaining rules. The Cassandra mirror delete fires ONLY when the scoped Postgres
     * delete actually removed a row — so a scoped admin's attempt to delete another
     * brand's rule (a no-op in Postgres) does not wipe that rule from the gateways'
     * read store either.
     */
    public Flux<RouteRule> remove(String id, PrincipalDomain scope) {
        return repo.delete(id, scope)
                .flatMap(rows -> rows > 0 ? mirror.delete(id).thenReturn(rows) : Mono.just(rows))
                .thenMany(repo.list(scope));
    }
}
