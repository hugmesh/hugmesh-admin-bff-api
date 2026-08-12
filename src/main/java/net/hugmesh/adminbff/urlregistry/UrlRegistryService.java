package net.hugmesh.adminbff.urlregistry;

import org.springframework.stereotype.Service;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

/**
 * Route-DEFINITION CRUD over hugmesh_gateway.url_registry (reactive). Cassandra
 * is the source of truth (the gateways poll this table directly via
 * {@code UrlRegistryService} and turn each row into a live route) — so unlike the
 * route-ACCESS flow there is no separate Postgres source + Cassandra mirror; the
 * write here is authoritative. {@code pathPrefix} is the primary key, so a POST
 * upserts.
 */
@Service
public class UrlRegistryService {

    private final UrlRegistryRepository repo;

    public UrlRegistryService(UrlRegistryRepository repo) {
        this.repo = repo;
    }

    public Flux<UrlRoute> list() {
        return repo.list();
    }

    public Mono<UrlRoute> upsert(UrlRoute route) {
        return repo.upsert(route);
    }

    public Flux<UrlRoute> remove(String pathPrefix) {
        return repo.delete(pathPrefix).thenMany(repo.list());
    }
}
