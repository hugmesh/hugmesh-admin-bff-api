package net.hugmesh.adminbff.routeaccess;

import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

/**
 * Mirrors route-access rules from the Postgres source of truth into the store
 * the gateways actually read (Cassandra gateway_route_access — see
 * hugmesh-gateway GatewayRouteAccessService). Best-effort: a mirror failure
 * must never fail the authoritative Postgres write. Reactive so the mirror runs
 * off the request-handling event loop (the blocking Cassandra driver is wrapped
 * on a bounded-elastic scheduler).
 */
public interface RouteMirror {
    Mono<Void> upsert(RouteRule rule);

    Mono<Void> delete(String id);

    /**
     * The ids CURRENTLY present in the mirror store
     * ({@code SELECT id FROM gateway_route_access}). Used by the delete-reconcile
     * (G4) to find orphan mirror rows whose authoritative Postgres rule was
     * deleted but whose per-write {@code mirror.delete} was swallowed. Best-effort
     * like the rest of the interface: when the mirror is disabled or Cassandra is
     * absent/unreachable/errors the read yields an EMPTY {@link Flux} (logged) so a
     * failed enumeration NEVER drives a prune.
     *
     * <p>DEFAULT is {@link Flux#empty()} so existing implementers/fakes stay source-
     * compatible and a mirror that cannot enumerate simply never contributes any
     * orphan to prune.
     */
    default Flux<String> listIds() {
        return Flux.empty();
    }
}
