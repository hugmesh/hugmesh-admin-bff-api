package net.hugmesh.adminbff;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webflux.test.autoconfigure.WebFluxTest;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.reactive.server.WebTestClient;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import net.hugmesh.authcore.account.AccountStore;
import net.hugmesh.authcore.casdoor.CasdoorAdminClient;
import net.hugmesh.adminbff.config.SecurityConfig;
import net.hugmesh.adminbff.domainlock.DomainLockService;
import net.hugmesh.adminbff.iso.IsoRepository;
import net.hugmesh.adminbff.routeaccess.RouteAccessService;
import net.hugmesh.commons.security.DomainRegistry;
import net.hugmesh.adminbff.suspension.SuspensionService;
import net.hugmesh.adminbff.urlregistry.UrlRoute;
import net.hugmesh.adminbff.urlregistry.UrlRegistryService;
import net.hugmesh.adminbff.usage.UsageService;
import net.hugmesh.authcore.username.UsernameGate;
import net.hugmesh.adminbff.web.ValidationExceptionHandler;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.mockJwt;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.springSecurity;

/**
 * Route DEFINITION endpoints (GET/POST/DELETE /bff/admin/routes) are
 * SUPERADMIN-only. The url_registry Cassandra table has no domain column,
 * making it a cluster-level resource — a brand-scoped ADMIN must not be
 * able to see or mutate another brand's route definitions (BFLA).
 * Route ACCESS rules (/bff/admin/route-access) are the domain-scoped
 * counterpart that brand admins can manage.
 */
@WebFluxTest(controllers = AdminController.class)
@Import({SecurityConfig.class, DomainRegistry.class, ValidationExceptionHandler.class})
class AdminControllerRouteDefinitionsTest {

    @Autowired ApplicationContext context;

    WebTestClient web;

    @BeforeEach
    void setup() {
        web = WebTestClient.bindToApplicationContext(context).apply(springSecurity()).build();
    }

    @MockitoBean RouteAccessService routeAccess;
    @MockitoBean UrlRegistryService urlRegistry;
    @MockitoBean IsoRepository isoRepo;
    @MockitoBean AccountStore store;
    @MockitoBean UsageService usage;
    @MockitoBean SuspensionService suspensions;
    @MockitoBean DomainLockService domainLocks;
    @MockitoBean net.hugmesh.adminbff.federation.FederationApiClient federation;
    @MockitoBean CasdoorAdminClient casdoor;
    @MockitoBean net.hugmesh.authcore.provision.GatewayRevocationClient revocations;
    @MockitoBean UsernameGate usernameGate;
    @MockitoBean ReactiveJwtDecoder jwtDecoder;

    private WebTestClient asSuperadmin() {
        return web.mutateWith(mockJwt().authorities(
                new SimpleGrantedAuthority("ROLE_USER"),
                new SimpleGrantedAuthority("ROLE_ADMIN"),
                new SimpleGrantedAuthority("ROLE_SUPERADMIN")));
    }

    private WebTestClient asAdmin() {
        // Brand-scoped ADMIN — must be denied on route definition endpoints
        return web.mutateWith(mockJwt().authorities(
                new SimpleGrantedAuthority("ROLE_USER"),
                new SimpleGrantedAuthority("ROLE_ADMIN")));
    }

    private WebTestClient asAnon() {
        return web;
    }

    private static UrlRoute sampleRoute() {
        return new UrlRoute("/api/svc", "http://svc:8080", "svc", null, null);
    }

    // ── GET /routes ────────────────────────────────────────────────────────────

    @Test
    void getRoutes_asSuperadmin_200() {
        when(urlRegistry.list()).thenReturn(Flux.just(sampleRoute()));

        asSuperadmin().get().uri("/bff/admin/routes")
                .exchange().expectStatus().isOk()
                .expectBody().jsonPath("$.routes[0].pathPrefix").isEqualTo("/api/svc");
    }

    @Test
    void getRoutes_asAdmin_403() {
        // BFLA gate: brand-scoped ADMIN must not read the cluster-wide url_registry
        asAdmin().get().uri("/bff/admin/routes")
                .exchange().expectStatus().isForbidden();
    }

    @Test
    void getRoutes_anon_401() {
        asAnon().get().uri("/bff/admin/routes")
                .exchange().expectStatus().isUnauthorized();
    }

    // ── POST /routes ───────────────────────────────────────────────────────────

    @Test
    void upsertRoute_asSuperadmin_200() {
        UrlRoute saved = sampleRoute();
        when(urlRegistry.upsert(any(UrlRoute.class))).thenReturn(Mono.just(saved));
        when(urlRegistry.list()).thenReturn(Flux.just(saved));

        asSuperadmin().post().uri("/bff/admin/routes")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"pathPrefix\":\"/api/svc\",\"downstreamUri\":\"http://svc:8080\"}")
                .exchange().expectStatus().isOk()
                .expectBody().jsonPath("$.upserted.pathPrefix").isEqualTo("/api/svc");
    }

    @Test
    void upsertRoute_asAdmin_403() {
        // BFLA gate: brand-scoped ADMIN must not write cluster-wide route definitions
        asAdmin().post().uri("/bff/admin/routes")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"pathPrefix\":\"/api/svc\",\"downstreamUri\":\"http://svc:8080\"}")
                .exchange().expectStatus().isForbidden();
    }

    @Test
    void upsertRoute_anon_401() {
        asAnon().post().uri("/bff/admin/routes")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"pathPrefix\":\"/api/svc\",\"downstreamUri\":\"http://svc:8080\"}")
                .exchange().expectStatus().isUnauthorized();
    }

    // ── DELETE /routes/{pathPrefix} ────────────────────────────────────────────

    @Test
    void removeRoute_asSuperadmin_200() {
        when(urlRegistry.remove("/api/svc")).thenReturn(Flux.empty());

        asSuperadmin().delete().uri("/bff/admin/routes/{prefix}", "/api/svc")
                .exchange().expectStatus().isOk()
                .expectBody().jsonPath("$.routes").isArray();
    }

    @Test
    void removeRoute_asAdmin_403() {
        // BFLA gate: brand-scoped ADMIN must not delete cluster-wide route definitions
        asAdmin().delete().uri("/bff/admin/routes/{prefix}", "/api/svc")
                .exchange().expectStatus().isForbidden();
    }

    @Test
    void removeRoute_anon_401() {
        asAnon().delete().uri("/bff/admin/routes/{prefix}", "/api/svc")
                .exchange().expectStatus().isUnauthorized();
    }
}
