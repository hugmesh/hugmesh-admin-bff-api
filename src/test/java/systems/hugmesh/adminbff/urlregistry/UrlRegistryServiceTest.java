package systems.hugmesh.adminbff.urlregistry;

import org.junit.jupiter.api.Test;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

/** Cassandra is authoritative for route DEFINITIONS — no separate mirror. */
class UrlRegistryServiceTest {

    private final UrlRegistryRepository repo = mock(UrlRegistryRepository.class);
    private final UrlRegistryService svc = new UrlRegistryService(repo);

    @Test
    void upsert_writesCassandraAndReturnsSavedRoute() {
        UrlRoute in = new UrlRoute("/api/games/", "http://games:8080", "hugmesh-games", null, null);
        when(repo.upsert(in)).thenReturn(Mono.just(in));

        UrlRoute out = svc.upsert(in).block();

        assertThat(out).isEqualTo(in);
        verify(repo).upsert(in);
    }

    @Test
    void upsert_carriesStripPrefixThroughToRepoAndBack() {
        // A route created WITH strip_prefix=1 round-trips that value through the
        // service to the repo and back in the saved route (no silent drop to 0).
        UrlRoute in = new UrlRoute("/be/", "http://backend:8080", "hugmesh-backend", null, 1);
        when(repo.upsert(in)).thenReturn(Mono.just(in));

        UrlRoute out = svc.upsert(in).block();

        assertThat(out).isEqualTo(in);
        assertThat(out.stripPrefix()).isEqualTo(1);
        verify(repo).upsert(in);
    }

    @Test
    void upsert_withoutStripPrefix_defaultsToNullNoStrip() {
        // Back-compat: a route created WITHOUT strip_prefix carries null ("no
        // strip"), the same sentinel the gateway and DTO use.
        UrlRoute in = new UrlRoute("/api/games/", "http://games:8080", "hugmesh-games", null, null);
        when(repo.upsert(in)).thenReturn(Mono.just(in));

        UrlRoute out = svc.upsert(in).block();

        assertThat(out.stripPrefix()).isNull();
        verify(repo).upsert(in);
    }

    @Test
    void remove_deletesAndReturnsCurrentList() {
        when(repo.delete("/api/games/")).thenReturn(Mono.empty());
        when(repo.list()).thenReturn(Flux.empty());

        var routes = svc.remove("/api/games/").collectList().block();

        assertThat(routes).isEmpty();
        verify(repo).delete("/api/games/");
        verify(repo).list();
    }
}
