package net.hugmesh.adminbff;
import org.junit.jupiter.api.BeforeEach;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.boot.webflux.test.autoconfigure.WebFluxTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.HttpMethod;
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
import net.hugmesh.commons.security.PrincipalDomain;
import net.hugmesh.adminbff.suspension.SuspensionService;
import net.hugmesh.adminbff.urlregistry.UrlRegistryService;
import net.hugmesh.adminbff.urlregistry.UrlRoute;
import net.hugmesh.adminbff.usage.UsageService;
import net.hugmesh.authcore.username.UsernameGate;
import net.hugmesh.adminbff.web.ValidationExceptionHandler;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.mockJwt;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.springSecurity;

/**
 * Bean-validation contract on the admin endpoints after the Map-body → typed-DTO
 * migration. Asserts the clean-400 + {error,fields} body, that an invalid body
 * never reaches the service layer, and that the new guards (UUID on route-access
 * delete; @Email/@Size on allowlist; @NotBlank on grant/route fields) fire. The
 * existing happy-path + reserved-name + role-gating behavior is covered in
 * AdminControllerRouteAccessTest / AdminControllerAllowlistTest.
 */
@WebFluxTest(controllers = AdminController.class)
@Import({SecurityConfig.class, DomainRegistry.class, ValidationExceptionHandler.class})
class AdminControllerValidationTest {

    @Autowired ApplicationContext context;

    WebTestClient web;

    @BeforeEach
    void setUpWebTestClient() {
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
        return web.mutateWith(mockJwt().authorities(
                new SimpleGrantedAuthority("ROLE_USER"), new SimpleGrantedAuthority("ROLE_ADMIN")));
    }

    // ── allowlist ───────────────────────────────────────────────────────
    @Test
    void invite_invalidEmail_400_andNoStoreWrite() {
        asAdmin().post().uri("/bff/admin/allowlist").contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"email\":\"not-an-email\"}")
                .exchange().expectStatus().isBadRequest()
                .expectBody()
                .jsonPath("$.error").isEqualTo("validation failed")
                .jsonPath("$.fields.email").exists();
        verify(store, never()).inviteEmail(anyString(), anyString());
    }

    // ── namespace-access ────────────────────────────────────────────────
    @Test
    void grant_blankUser_400() {
        asAdmin().post().uri("/bff/admin/namespace-access").contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"user\":\"\",\"namespace\":\"observability\"}")
                .exchange().expectStatus().isBadRequest()
                .expectBody().jsonPath("$.fields.user").exists();
        verify(store, never()).grant(anyString(), anyString(), anyString());
    }

    @Test
    void grant_missingNamespace_400() {
        asAdmin().post().uri("/bff/admin/namespace-access").contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"user\":\"bob\"}")
                .exchange().expectStatus().isBadRequest()
                .expectBody().jsonPath("$.fields.namespace").exists();
    }

    // ── route-access add ────────────────────────────────────────────────
    @Test
    void addRouteRule_missingRole_400_andNoAdd() {
        asAdmin().post().uri("/bff/admin/route-access").contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"gateway\":\"gw\",\"url_pattern\":\"/api/**\"}")
                .exchange().expectStatus().isBadRequest()
                .expectBody().jsonPath("$.fields.role").exists();
        verify(routeAccess, never()).add(any());
    }

    @Test
    void addRouteRule_urlPatternWithoutLeadingSlash_400() {
        // The field-error key is the record-component name (urlPattern), not the
        // @JsonProperty alias — Spring's binding reports the bean property path.
        asAdmin().post().uri("/bff/admin/route-access").contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"gateway\":\"gw\",\"url_pattern\":\"api/**\",\"role\":\"ROLE_ADMIN\"}")
                .exchange().expectStatus().isBadRequest()
                .expectBody().jsonPath("$.fields.urlPattern").exists();
        verify(routeAccess, never()).add(any());
    }

    // ── route-access delete (UUID guard) ────────────────────────────────
    @Test
    void removeRouteRule_malformedId_400_neverCallsRemove() {
        // A non-UUID id previously reached RouteAccessRepository.delete and threw
        // IllegalArgumentException (500); now it is a clean 400 at the edge.
        asAdmin().method(HttpMethod.DELETE).uri("/bff/admin/route-access")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"id\":\"not-a-uuid\"}")
                .exchange().expectStatus().isBadRequest()
                .expectBody().jsonPath("$.fields.id").exists();
        verify(routeAccess, never()).remove(anyString(), any(PrincipalDomain.class));
    }

    @Test
    void removeRouteRule_validUuid_passesValidation() {
        when(routeAccess.remove(org.mockito.ArgumentMatchers.eq("11111111-2222-3333-4444-555555555555"), any(PrincipalDomain.class))).thenReturn(Flux.empty());
        asAdmin().method(HttpMethod.DELETE).uri("/bff/admin/route-access")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"id\":\"11111111-2222-3333-4444-555555555555\"}")
                .exchange().expectStatus().isOk();
        verify(routeAccess).remove(org.mockito.ArgumentMatchers.eq("11111111-2222-3333-4444-555555555555"), any(PrincipalDomain.class));
    }

    // ── routes upsert (SUPERADMIN-only; auth runs before validation) ────────────
    @Test
    void upsertRoute_missingDownstream_400() {
        asSuperadmin().post().uri("/bff/admin/routes").contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"pathPrefix\":\"/api/games/\"}")
                .exchange().expectStatus().isBadRequest()
                .expectBody().jsonPath("$.fields.downstreamUri").exists();
        verify(urlRegistry, never()).upsert(any());
    }

    @Test
    void upsertRoute_negativeStripPrefix_400_andNoUpsert() {
        // @PositiveOrZero rejects a negative strip_prefix at the edge; the field-error
        // key is the record-component name (stripPrefix), not the @JsonProperty alias.
        asSuperadmin().post().uri("/bff/admin/routes").contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"pathPrefix\":\"/be/\",\"downstreamUri\":\"http://be:8080\",\"stripPrefix\":-1}")
                .exchange().expectStatus().isBadRequest()
                .expectBody().jsonPath("$.fields.stripPrefix").exists();
        verify(urlRegistry, never()).upsert(any());
    }

    @Test
    void upsertRoute_withStripPrefix_passesItToUpsert() {
        // A route created WITH strip_prefix=1 threads that value into the UrlRoute
        // handed to the service (so the gateway later emits StripPrefix=1).
        UrlRoute saved = new UrlRoute("/be/", "http://be:8080", null, null, 1);
        when(urlRegistry.upsert(argThat(r -> r != null && r.stripPrefix() != null && r.stripPrefix() == 1)))
                .thenReturn(Mono.just(saved));
        when(urlRegistry.list()).thenReturn(Flux.just(saved));

        asSuperadmin().post().uri("/bff/admin/routes").contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"pathPrefix\":\"/be/\",\"downstreamUri\":\"http://be:8080\",\"stripPrefix\":1}")
                .exchange().expectStatus().isOk()
                .expectBody().jsonPath("$.upserted.stripPrefix").isEqualTo(1);

        verify(urlRegistry).upsert(argThat(r -> r.stripPrefix() != null && r.stripPrefix() == 1));
    }

    @Test
    void upsertRoute_withoutStripPrefix_defaultsToNull_backCompat() {
        // Back-compat: an existing caller that omits strip_prefix still works, and the
        // UrlRoute carries null (no strip) — the controller does not invent a value.
        UrlRoute saved = new UrlRoute("/api/games/", "http://games:8080", null, null, null);
        when(urlRegistry.upsert(argThat(r -> r != null && r.stripPrefix() == null)))
                .thenReturn(Mono.just(saved));
        when(urlRegistry.list()).thenReturn(Flux.just(saved));

        asSuperadmin().post().uri("/bff/admin/routes").contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"pathPrefix\":\"/api/games/\",\"downstreamUri\":\"http://games:8080\"}")
                .exchange().expectStatus().isOk();

        verify(urlRegistry).upsert(argThat(r -> r.stripPrefix() == null));
    }
}
