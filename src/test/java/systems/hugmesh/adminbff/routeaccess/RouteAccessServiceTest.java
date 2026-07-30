package systems.hugmesh.adminbff.routeaccess;

import org.junit.jupiter.api.Test;
import org.mockito.InOrder;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import systems.hugmesh.commons.security.DomainRegistry;
import systems.hugmesh.commons.security.PrincipalDomain;

import java.time.Instant;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

/** Postgres is authoritative; the Cassandra mirror runs AFTER, best-effort. The
 *  service surface is DOMAIN-SCOPED — these baseline tests act as SUPERADMIN
 *  (unscoped) so the add/remore ordering assertions are unaffected; the per-tenant
 *  filtering is covered in {@link RouteAccessRepositoryTest}. */
class RouteAccessServiceTest {

    private final RouteAccessRepository repo = mock(RouteAccessRepository.class);
    private final RouteMirror mirror = mock(RouteMirror.class);
    private final RouteAccessService svc = new RouteAccessService(repo, mirror);

    /** A SUPERADMIN (unscoped) scope. */
    private static PrincipalDomain superadmin() {
        Jwt jwt = Jwt.withTokenValue("t").header("alg", "none")
                .issuedAt(Instant.now()).expiresAt(Instant.now().plusSeconds(3600))
                .subject("u").claim("roles", List.of("superadmin")).build();
        var auth = new JwtAuthenticationToken(jwt,
                List.of(new SimpleGrantedAuthority("ROLE_USER"), new SimpleGrantedAuthority("ROLE_SUPERADMIN")));
        return PrincipalDomain.of(auth, new DomainRegistry("", ""));
    }

    @Test
    void add_writesPostgresThenMirrors_withTheSavedRow() {
        RouteRule in = new RouteRule(null, "hugmesh-be-gateway", "/api/admin/**", "ROLE_ADMIN", null, true, "default");
        RouteRule saved = new RouteRule("id-1", "hugmesh-be-gateway", "/api/admin/**", "ROLE_ADMIN", null, true, "default");
        when(repo.add(in)).thenReturn(Mono.just(saved));
        when(mirror.upsert(saved)).thenReturn(Mono.empty());

        RouteRule out = svc.add(in).block();

        assertThat(out).isEqualTo(saved);
        InOrder order = inOrder(repo, mirror);
        order.verify(repo).add(in);          // authoritative write first
        order.verify(mirror).upsert(saved);  // then mirror the persisted row (with id)
    }

    @Test
    void remove_deletesFromBothAndReturnsCurrentList_whenRowWasInScope() {
        PrincipalDomain scope = superadmin();
        when(repo.delete(eq("id-1"), any(PrincipalDomain.class))).thenReturn(Mono.just(1L));
        when(mirror.delete("id-1")).thenReturn(Mono.empty());
        when(repo.list(any(PrincipalDomain.class))).thenReturn(Flux.empty());

        var rules = svc.remove("id-1", scope).collectList().block();

        assertThat(rules).isEmpty();
        verify(repo).delete(eq("id-1"), any(PrincipalDomain.class));
        verify(mirror).delete("id-1");
        verify(repo).list(any(PrincipalDomain.class));
    }

    @Test
    void remove_doesNotMirrorDelete_whenScopedDeleteRemovedNothing() {
        // A scoped admin deleting another brand's id removes 0 Postgres rows → the
        // Cassandra mirror is NOT wiped for that other-brand rule either.
        PrincipalDomain scope = superadmin();
        when(repo.delete(eq("id-x"), any(PrincipalDomain.class))).thenReturn(Mono.just(0L));
        when(repo.list(any(PrincipalDomain.class))).thenReturn(Flux.empty());

        svc.remove("id-x", scope).collectList().block();

        verify(repo).delete(eq("id-x"), any(PrincipalDomain.class));
        verify(mirror, never()).delete(anyString());
    }
}
