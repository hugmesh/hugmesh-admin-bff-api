package net.hugmesh.adminbff;
import org.junit.jupiter.api.BeforeEach;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.boot.webflux.test.autoconfigure.WebFluxTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.reactive.server.WebTestClient;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import net.hugmesh.authcore.account.AccountStore;
import net.hugmesh.authcore.casdoor.CasdoorAdminClient;
import net.hugmesh.adminbff.config.SecurityConfig;
import net.hugmesh.adminbff.domainlock.DomainLockService;
import net.hugmesh.adminbff.iso.IsoArtifact;
import net.hugmesh.adminbff.iso.IsoRepository;
import net.hugmesh.adminbff.routeaccess.RouteAccessService;
import net.hugmesh.adminbff.routeaccess.RouteRule;
import net.hugmesh.commons.security.DomainRegistry;
import net.hugmesh.commons.security.PrincipalDomain;
import net.hugmesh.adminbff.suspension.SuspensionService;
import net.hugmesh.adminbff.urlregistry.UrlRegistryService;
import net.hugmesh.adminbff.urlregistry.UrlRoute;
import net.hugmesh.adminbff.usage.UsageService;
import net.hugmesh.authcore.username.UsernameGate;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.mockJwt;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.springSecurity;

/**
 * Route-access + ISO endpoint contract (shape per mock-bff.mjs) and admin gating,
 * now reactive: @WebFluxTest + WebTestClient + mockJwt() + a mocked
 * ReactiveJwtDecoder to satisfy the resource-server wiring. @PreAuthorize is active
 * via @EnableReactiveMethodSecurity in SecurityConfig. CSRF is disabled, so
 * POST/DELETE need no token.
 */
@WebFluxTest(controllers = AdminController.class)
@Import({SecurityConfig.class, DomainRegistry.class})
class AdminControllerRouteAccessTest {

    @Autowired ApplicationContext context;

    WebTestClient web;

    @BeforeEach
    void setUpWebTestClient() {
        web = WebTestClient.bindToApplicationContext(context).apply(springSecurity()).build();
    }

    @MockitoBean RouteAccessService routeAccess;
    @MockitoBean UrlRegistryService urlRegistry;
    @MockitoBean IsoRepository isoRepo;
    @MockitoBean AccountStore store;            // allowlist/namespace state (mocked here)
    @MockitoBean UsageService usage;            // usage recorder/aggregator (mocked here)
    @MockitoBean SuspensionService suspensions; // access-suspension desired-state (mocked here)
    @MockitoBean DomainLockService domainLocks; // domain-lock desired-state (mocked here)
    @MockitoBean net.hugmesh.adminbff.federation.FederationApiClient federation; // appeals decide-proxy (mocked here)
    @MockitoBean CasdoorAdminClient casdoor;    // real Casdoor write client (mocked here)
    @MockitoBean net.hugmesh.authcore.provision.GatewayRevocationClient revocations;
    @MockitoBean UsernameGate usernameGate;     // username-derivation gate (mocked here)
    @MockitoBean net.hugmesh.adminbff.capability.DomainCapabilityService domainCapabilities; // external-client gate (mocked here)
    @MockitoBean ReactiveJwtDecoder jwtDecoder; // satisfies oauth2 resource server wiring

    private WebTestClient asSuperadmin() {
        return web.mutateWith(mockJwt().authorities(
                new org.springframework.security.core.authority.SimpleGrantedAuthority("ROLE_USER"),
                new org.springframework.security.core.authority.SimpleGrantedAuthority("ROLE_ADMIN"),
                new org.springframework.security.core.authority.SimpleGrantedAuthority("ROLE_SUPERADMIN")));
    }

    private WebTestClient asAdmin() {
        return web.mutateWith(mockJwt().authorities(
                new org.springframework.security.core.authority.SimpleGrantedAuthority("ROLE_USER"),
                new org.springframework.security.core.authority.SimpleGrantedAuthority("ROLE_ADMIN")));
    }

    private WebTestClient asUser() {
        return web.mutateWith(mockJwt().authorities(
                new org.springframework.security.core.authority.SimpleGrantedAuthority("ROLE_USER")));
    }

    @Test
    void getRouteAccess_returnsRulesWithContractFieldNames() {
        when(routeAccess.list(any(PrincipalDomain.class))).thenReturn(Flux.just(
                new RouteRule("id-1", "hugmesh-be-gateway", "/api/**", "ROLE_USER", null, true, "default")));
        asAdmin().get().uri("/bff/admin/route-access").exchange()
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$.rules[0].gateway").isEqualTo("hugmesh-be-gateway")
                .jsonPath("$.rules[0].url_pattern").isEqualTo("/api/**")
                .jsonPath("$.rules[0].role").isEqualTo("ROLE_USER")
                .jsonPath("$.rules[0].allow").isEqualTo(true);
    }

    @Test
    void getRouteAccess_forbiddenForNonAdmin() {
        asUser().get().uri("/bff/admin/route-access").exchange().expectStatus().isForbidden();
    }

    @Test
    void postRouteRule_400WhenRequiredFieldsMissing() {
        asAdmin().post().uri("/bff/admin/route-access").contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"gateway\":\"hugmesh-be-gateway\"}")
                .exchange().expectStatus().isBadRequest();
    }

    @Test
    void postRouteRule_addsAndReturnsRulesPlusAdded() {
        // addRouteRule records a usage event (fire-and-forget); stub it so the
        // mocked UsageService returns a real Mono rather than null (as the
        // allowlist/namespace tests do for the same usage.record call).
        when(usage.record(org.mockito.ArgumentMatchers.anyString(), any(),
                org.mockito.ArgumentMatchers.anyString())).thenReturn(Mono.empty());
        RouteRule added = new RouteRule("id-9", "hugmesh-be-gateway", "/api/admin/**", "ROLE_ADMIN", null, true, "default");
        when(routeAccess.add(any())).thenReturn(Mono.just(added));
        when(routeAccess.list(any(PrincipalDomain.class))).thenReturn(Flux.just(added));
        asAdmin().post().uri("/bff/admin/route-access").contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"gateway\":\"hugmesh-be-gateway\",\"url_pattern\":\"/api/admin/**\",\"role\":\"ROLE_ADMIN\"}")
                .exchange().expectStatus().isOk()
                .expectBody()
                .jsonPath("$.added.id").isEqualTo("id-9")
                .jsonPath("$.rules[0].role").isEqualTo("ROLE_ADMIN")
                // /api/** first segment 'api' IS reserved → no warning emitted.
                .jsonPath("$.reservedWarning").doesNotExist();
    }

    @Test
    void postRouteRule_warnsWhenFirstSegmentIsNotYetReserved() {
        when(usage.record(org.mockito.ArgumentMatchers.anyString(), any(),
                org.mockito.ArgumentMatchers.anyString())).thenReturn(Mono.empty());
        RouteRule added = new RouteRule("id-w", "hugmesh-fe-gateway", "/widgets/**", "ROLE_USER", null, true, "default");
        when(routeAccess.add(any())).thenReturn(Mono.just(added));
        when(routeAccess.list(any(PrincipalDomain.class))).thenReturn(Flux.just(added));
        // 'widgets' is a NEW dedicated prefix not yet in the reserved set →
        // the rule is still added, but a reservedWarning is returned.
        asAdmin().post().uri("/bff/admin/route-access").contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"gateway\":\"hugmesh-fe-gateway\",\"url_pattern\":\"/widgets/**\",\"role\":\"ROLE_USER\"}")
                .exchange().expectStatus().isOk()
                .expectBody()
                .jsonPath("$.added.id").isEqualTo("id-w")
                .jsonPath("$.reservedWarning").value(org.hamcrest.Matchers.containsString("widgets"))
                // The warning must direct operators at the REAL sync chain (the
                // canonical YAML + the auth-core shared copy), not the deleted
                // in-repo duplicate the old text named.
                .jsonPath("$.reservedWarning").value(org.hamcrest.Matchers.containsString("reserved-prefixes.yaml"))
                .jsonPath("$.reservedWarning").value(org.hamcrest.Matchers.containsString("hugmesh-auth-core"))
                .jsonPath("$.reservedWarning").value(org.hamcrest.Matchers.not(
                        org.hamcrest.Matchers.containsString("in hugmesh-admin-bff-api")));
    }

    @Test
    void postRouteRule_noWarningForCharacterForgePrefix_nowInAuthCoreReservedSet() {
        when(usage.record(org.mockito.ArgumentMatchers.anyString(), any(),
                org.mockito.ArgumentMatchers.anyString())).thenReturn(Mono.empty());
        RouteRule added = new RouteRule("id-cf", "hugmesh-fe-gateway", "/character-forge/**", "ROLE_USER", null, true, "default");
        when(routeAccess.add(any())).thenReturn(Mono.just(added));
        when(routeAccess.list(any(PrincipalDomain.class))).thenReturn(Flux.just(added));
        // RUNTIME proof of the auth-core 2.4.1 pin: 'character-forge' (canonical
        // reserved-prefixes.yaml revision 9, the Character Forge fe-gateway route)
        // is now IN the shared ReservedNames set this warning consults, so seeding
        // its route-access rule emits NO drift warning. Before the pin bump this
        // exact request produced a reservedWarning (the label was missing from the
        // pinned jar) — a downgrade regresses this test.
        asAdmin().post().uri("/bff/admin/route-access").contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"gateway\":\"hugmesh-fe-gateway\",\"url_pattern\":\"/character-forge/**\",\"role\":\"ROLE_USER\"}")
                .exchange().expectStatus().isOk()
                .expectBody()
                .jsonPath("$.added.id").isEqualTo("id-cf")
                .jsonPath("$.reservedWarning").doesNotExist();
    }

    @Test
    void postRouteRule_400WhenPatternHasNoAddressableSegment() {
        // A bare-wildcard pattern can't target a dedicated prefix → rejected
        // before any write (routeAccess.add is never reached).
        asAdmin().post().uri("/bff/admin/route-access").contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"gateway\":\"hugmesh-fe-gateway\",\"url_pattern\":\"/**\",\"role\":\"ROLE_USER\"}")
                .exchange().expectStatus().isBadRequest();
    }

    @Test
    void postRouteRule_400WhenPatternIsBareSingleWildcard() {
        // Same rejection for '/*' — a bare single-segment wildcard is exactly
        // as unaddressable as '/**'. hugmesh-admin-bff-api#57 / decision 61.
        asAdmin().post().uri("/bff/admin/route-access").contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"gateway\":\"hugmesh-fe-gateway\",\"url_pattern\":\"/*\",\"role\":\"ROLE_USER\"}")
                .exchange().expectStatus().isBadRequest();
    }

    @Test
    void postRouteRule_acceptsBareRootSlash_theOneExplicitException() {
        // '/' is the ONE pattern with no addressable first segment the API
        // still accepts — a single literal path, not a wildcard catch-all, so
        // it can never silently widen. Companion of the two 400 tests above:
        // proves the exception is narrow (exactly '/', not "anything without a
        // segment"). hugmesh-admin-bff-api#57 / decision 61 (refuse '/**',
        // hugmesh-generator#347, 2026-09-18) leans on this being the ONLY hole.
        when(usage.record(org.mockito.ArgumentMatchers.anyString(), any(),
                org.mockito.ArgumentMatchers.anyString())).thenReturn(Mono.empty());
        RouteRule added = new RouteRule("id-root", "hugmesh-fe-gateway", "/", "PUBLIC", null, true, "default");
        when(routeAccess.add(any())).thenReturn(Mono.just(added));
        when(routeAccess.list(any(PrincipalDomain.class))).thenReturn(Flux.just(added));
        asAdmin().post().uri("/bff/admin/route-access").contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"gateway\":\"hugmesh-fe-gateway\",\"url_pattern\":\"/\",\"role\":\"PUBLIC\"}")
                .exchange().expectStatus().isOk()
                .expectBody()
                .jsonPath("$.added.id").isEqualTo("id-root");
    }

    // ── DB-driven route DEFINITIONS (url_registry, SUPERADMIN-only) ──────────
    // Route definitions are cluster-level infrastructure (the url_registry
    // Cassandra table has no domain column). SUPERADMIN is required; a
    // brand-scoped ADMIN is denied (cross-tenant BFLA prevention).
    @Test
    void getRoutes_returnsRouteDefinitions() {
        when(urlRegistry.list()).thenReturn(Flux.just(
                new UrlRoute("/api/games/", "http://games:8080", "hugmesh-games", "ROLE_USER", 1)));
        asSuperadmin().get().uri("/bff/admin/routes").exchange()
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$.routes[0].pathPrefix").isEqualTo("/api/games/")
                .jsonPath("$.routes[0].downstreamUri").isEqualTo("http://games:8080")
                .jsonPath("$.routes[0].serviceName").isEqualTo("hugmesh-games")
                .jsonPath("$.routes[0].requiredRole").isEqualTo("ROLE_USER")
                // strip_prefix surfaces in the route list the admin UI reads.
                .jsonPath("$.routes[0].stripPrefix").isEqualTo(1);
    }

    @Test
    void getRoutes_forbiddenForAdmin() {
        // BFLA gate: brand-scoped ADMIN must not read the cluster-wide url_registry.
        // (Use the dedicated AdminControllerRouteDefinitionsTest for the full
        // superadmin/admin/anon matrix.)
        asAdmin().get().uri("/bff/admin/routes").exchange().expectStatus().isForbidden();
    }

    @Test
    void postRoute_400WhenRequiredFieldsMissing() {
        asSuperadmin().post().uri("/bff/admin/routes").contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"pathPrefix\":\"/api/games/\"}")
                .exchange().expectStatus().isBadRequest();
    }

    @Test
    void postRoute_upsertsAndReturnsRoutesPlusUpserted() {
        UrlRoute saved = new UrlRoute("/api/games/", "http://games:8080", "hugmesh-games", null, null);
        when(urlRegistry.upsert(any())).thenReturn(Mono.just(saved));
        when(urlRegistry.list()).thenReturn(Flux.just(saved));
        asSuperadmin().post().uri("/bff/admin/routes").contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"pathPrefix\":\"/api/games/\",\"downstreamUri\":\"http://games:8080\",\"serviceName\":\"hugmesh-games\"}")
                .exchange().expectStatus().isOk()
                .expectBody()
                .jsonPath("$.upserted.pathPrefix").isEqualTo("/api/games/")
                .jsonPath("$.routes[0].downstreamUri").isEqualTo("http://games:8080")
                // first segment 'api' is reserved → no warning.
                .jsonPath("$.reservedWarning").doesNotExist();
    }

    @Test
    void postRoute_warnsWhenDefiningANewNonReservedPrefix() {
        UrlRoute saved = new UrlRoute("/widgets/", "http://widgets:8080", "hugmesh-widgets", null, null);
        when(urlRegistry.upsert(any())).thenReturn(Mono.just(saved));
        when(urlRegistry.list()).thenReturn(Flux.just(saved));
        // Defining a route under a brand-new prefix is where the reserved set
        // can fall out of date → the upsert succeeds but warns.
        asSuperadmin().post().uri("/bff/admin/routes").contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"pathPrefix\":\"/widgets/\",\"downstreamUri\":\"http://widgets:8080\",\"serviceName\":\"hugmesh-widgets\"}")
                .exchange().expectStatus().isOk()
                .expectBody()
                .jsonPath("$.upserted.pathPrefix").isEqualTo("/widgets/")
                .jsonPath("$.reservedWarning").value(org.hamcrest.Matchers.containsString("widgets"));
    }

    @Test
    void postRoute_400WhenPrefixHasNoAddressableSegment() {
        asSuperadmin().post().uri("/bff/admin/routes").contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"pathPrefix\":\"/**\",\"downstreamUri\":\"http://x:8080\"}")
                .exchange().expectStatus().isBadRequest();
    }

    @Test
    void deleteRoute_removesByUrlEncodedPrefix() {
        when(urlRegistry.remove("/api/games/")).thenReturn(Flux.empty());
        // path_prefix "/api/games/" URL-encoded into a single path segment. The
        // reactive stack decodes %2F into the {pathPrefix} variable. Pass a
        // pre-encoded URI (URI.create) so WebTestClient does NOT re-encode the
        // '%' of the already-percent-encoded slashes into %25 (which would 400).
        asSuperadmin().delete().uri(java.net.URI.create("/bff/admin/routes/%2Fapi%2Fgames%2F")).exchange()
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$.routes").isEmpty();
    }

    // ── Reserved-username gate on provisioning (namespace grant) ─────────
    @Test
    void grantNamespace_rejectsReservedUsername() {
        // 'admin' is a reserved username → provisioning (granting) it is
        // rejected 400 BEFORE the store is touched.
        when(store.isValidNamespace("hugmesh-pki")).thenReturn(true);
        asAdmin().post().uri("/bff/admin/namespace-access").contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"user\":\"admin\",\"namespace\":\"hugmesh-pki\"}")
                .exchange().expectStatus().isBadRequest()
                .expectBody().jsonPath("$.error").value(org.hamcrest.Matchers.containsString("reserved"));
        org.mockito.Mockito.verify(store, org.mockito.Mockito.never())
                .grant(org.mockito.ArgumentMatchers.anyString(), org.mockito.ArgumentMatchers.anyString(),
                        org.mockito.ArgumentMatchers.anyString());
    }

    @Test
    void grantNamespace_rejectsReservedHandleInProviderId() {
        // A "provider:handle" grantee whose handle is reserved is rejected too.
        when(store.isValidNamespace("hugmesh-pki")).thenReturn(true);
        asAdmin().post().uri("/bff/admin/namespace-access").contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"user\":\"discord:games\",\"namespace\":\"hugmesh-pki\"}")
                .exchange().expectStatus().isBadRequest()
                .expectBody().jsonPath("$.error").value(org.hamcrest.Matchers.containsString("reserved"));
    }

    @Test
    void grantNamespace_allowsOrdinaryUsername() {
        when(store.isValidNamespace("hugmesh-pki")).thenReturn(true);
        when(store.grant(org.mockito.ArgumentMatchers.eq("alice"), org.mockito.ArgumentMatchers.eq("hugmesh-pki"),
                org.mockito.ArgumentMatchers.anyString())).thenReturn(Mono.empty());
        when(store.allGrants()).thenReturn(Mono.just(java.util.List.of()));
        // Post-grant the controller re-reads via namespaceOut(scope), which is domain-scoped
        // (#19) → store.allGrants(domain); stub that overload too or it returns null → 500.
        when(store.allGrants(org.mockito.ArgumentMatchers.any())).thenReturn(Mono.just(java.util.List.of()));
        when(usage.record(org.mockito.ArgumentMatchers.anyString(), any(),
                org.mockito.ArgumentMatchers.anyString())).thenReturn(Mono.empty());
        asAdmin().post().uri("/bff/admin/namespace-access").contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"user\":\"alice\",\"namespace\":\"hugmesh-pki\"}")
                .exchange().expectStatus().isOk();
        org.mockito.Mockito.verify(store).grant(org.mockito.ArgumentMatchers.eq("alice"),
                org.mockito.ArgumentMatchers.eq("hugmesh-pki"), org.mockito.ArgumentMatchers.anyString());
    }

    @Test
    void isos_returnsList() {
        when(isoRepo.list()).thenReturn(Flux.just(
                new IsoArtifact("rpi5-pki.iso", "https://artifacts/rpi5-pki.iso")));
        asAdmin().get().uri("/bff/admin/isos").exchange()
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$.isos[0].name").isEqualTo("rpi5-pki.iso")
                .jsonPath("$.isos[0].url").isEqualTo("https://artifacts/rpi5-pki.iso");
    }
}
