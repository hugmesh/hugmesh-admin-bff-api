package net.hugmesh.adminbff.theme;

import net.hugmesh.adminbff.config.SecurityConfig;
import net.hugmesh.adminbff.web.ApiExceptionHandler;
import net.hugmesh.adminbff.web.ValidationExceptionHandler;
import net.hugmesh.commons.security.PrincipalDomain;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webflux.test.autoconfigure.WebFluxTest;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Import;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.springframework.web.server.ResponseStatusException;
import reactor.core.publisher.Mono;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.mockJwt;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.springSecurity;

/**
 * Web-layer contract for per-domain themes.
 *
 * <p>Two things here are load-bearing beyond ordinary CRUD wiring:
 *
 * <ol>
 *   <li>The {@code _default} path segment. The mesh default's storage key is the EMPTY
 *       string, which cannot be a URL path segment, so it needs a name — and that name
 *       must be one no real domain can take, or a brand could hijack the row every other
 *       brand inherits. The underscore is what guarantees that ({@code [a-z0-9-]} is the
 *       sanitized alphabet), and these tests pin that it maps to the empty key rather
 *       than to a domain literally called "_default".</li>
 *   <li>That the controller does NOT decide authorization. It forwards the scope and
 *       lets {@link DomainThemeService} refuse, so the 403 tests assert the service was
 *       CALLED — a controller that pre-empted the check would pass a shallower test while
 *       creating the second copy of a rule that has already drifted once on this
 *       platform.</li>
 * </ol>
 */
@WebFluxTest(controllers = DomainThemeAdminController.class)
@Import({SecurityConfig.class, net.hugmesh.commons.security.DomainRegistry.class,
        ValidationExceptionHandler.class, ApiExceptionHandler.class})
class DomainThemeAdminControllerTest {

    @Autowired ApplicationContext context;

    WebTestClient web;

    @BeforeEach
    void setUpWebTestClient() {
        web = WebTestClient.bindToApplicationContext(context).apply(springSecurity()).build();
    }

    @MockitoBean DomainThemeService service;
    @MockitoBean ReactiveJwtDecoder jwtDecoder;
    @MockitoBean net.hugmesh.authcore.provision.GatewayRevocationClient revocations;

    private WebTestClient asAdmin() {
        return web.mutateWith(mockJwt().authorities(
                new SimpleGrantedAuthority("ROLE_USER"), new SimpleGrantedAuthority("ROLE_ADMIN")));
    }

    private WebTestClient asUser() {
        return web.mutateWith(mockJwt().authorities(new SimpleGrantedAuthority("ROLE_USER")));
    }

    private static DomainTheme row(String domain) {
        return new DomainTheme(domain, "nord", "dusk", "sharp", null, null, "admin@x");
    }

    private static final String VALID_BODY =
            "{\"preset\":\"nord\",\"ramp\":\"dusk\",\"style\":\"sharp\"}";

    // ── the reserved default segment ────────────────────────────────────

    @Test
    void putDefaultSegment_targetsTheEmptyMeshDefaultKey_notADomainNamedDefault() {
        when(service.set(any(DomainTheme.class), any(PrincipalDomain.class), anyString()))
                .thenReturn(Mono.just(row(DomainTheme.MESH_DEFAULT)));

        asAdmin().put().uri("/bff/admin/themes/_default").contentType(MediaType.APPLICATION_JSON)
                .bodyValue(VALID_BODY)
                .exchange().expectStatus().isOk();

        verify(service).set(
                org.mockito.ArgumentMatchers.argThat(t -> t.domain().equals(DomainTheme.MESH_DEFAULT)),
                any(PrincipalDomain.class), anyString());
    }

    @Test
    void deleteDefaultSegment_clearsTheMeshDefaultKey() {
        when(service.clear(anyString(), any(PrincipalDomain.class))).thenReturn(Mono.empty());

        asAdmin().delete().uri("/bff/admin/themes/_default")
                .exchange().expectStatus().isNoContent();

        verify(service).clear(eq(DomainTheme.MESH_DEFAULT), any(PrincipalDomain.class));
    }

    @Test
    void anOrdinaryDomainSegmentIsPassedThroughAsItself() {
        when(service.set(any(DomainTheme.class), any(PrincipalDomain.class), anyString()))
                .thenReturn(Mono.just(row("brandx")));

        asAdmin().put().uri("/bff/admin/themes/brandx").contentType(MediaType.APPLICATION_JSON)
                .bodyValue(VALID_BODY)
                .exchange().expectStatus().isOk();

        verify(service).set(
                org.mockito.ArgumentMatchers.argThat(t -> t.domain().equals("brandx")),
                any(PrincipalDomain.class), anyString());
    }

    @Test
    void aDomainSpelledLikeTheSentinelCannotReachTheDefaultUnderAnotherName() {
        // "no-domain" normalises to the mesh-default key rather than becoming its own
        // row, so the service still gets ONE canonical target to authorize.
        when(service.set(any(DomainTheme.class), any(PrincipalDomain.class), anyString()))
                .thenReturn(Mono.just(row(DomainTheme.MESH_DEFAULT)));

        asAdmin().put().uri("/bff/admin/themes/no-domain").contentType(MediaType.APPLICATION_JSON)
                .bodyValue(VALID_BODY)
                .exchange().expectStatus().isOk();

        verify(service).set(
                org.mockito.ArgumentMatchers.argThat(t -> t.domain().equals(DomainTheme.MESH_DEFAULT)),
                any(PrincipalDomain.class), anyString());
    }

    // ── authorization stays in the service ──────────────────────────────

    @Test
    void aServiceRefusalSurfacesAs403_andTheControllerDidNotPreEmptIt() {
        when(service.set(any(DomainTheme.class), any(PrincipalDomain.class), anyString()))
                .thenReturn(Mono.error(new ResponseStatusException(HttpStatus.FORBIDDEN, "nope")));

        asAdmin().put().uri("/bff/admin/themes/brandy").contentType(MediaType.APPLICATION_JSON)
                .bodyValue(VALID_BODY)
                .exchange().expectStatus().isForbidden();

        // The point: the request REACHED the service. The controller forwards the scope
        // and lets the one authorization rule decide.
        verify(service).set(any(DomainTheme.class), any(PrincipalDomain.class), anyString());
    }

    @Test
    void aNonAdminIsRefusedBeforeTheServiceIsTouchedAtAll() {
        asUser().put().uri("/bff/admin/themes/brandx").contentType(MediaType.APPLICATION_JSON)
                .bodyValue(VALID_BODY)
                .exchange().expectStatus().isForbidden();
        verify(service, never()).set(any(), any(), anyString());
    }

    @Test
    void anonymousIsRefused() {
        web.put().uri("/bff/admin/themes/brandx").contentType(MediaType.APPLICATION_JSON)
                .bodyValue(VALID_BODY)
                .exchange().expectStatus().isUnauthorized();
        verify(service, never()).set(any(), any(), anyString());
    }

    @Test
    void getIsGuardedByCanManage_and403sWithoutResolvingTheTheme() {
        when(service.canManage(any(), anyString())).thenReturn(false);

        asAdmin().get().uri("/bff/admin/themes/brandy")
                .exchange().expectStatus().isForbidden();

        verify(service, never()).effective(anyString());
    }

    @Test
    void getReturnsTheEffectiveThemeAndWhetherItIsInherited() {
        when(service.canManage(any(), anyString())).thenReturn(true);
        when(service.effective(eq("brandx")))
                .thenReturn(Mono.just(new DomainThemeService.Effective(row("brandx"), true)));

        asAdmin().get().uri("/bff/admin/themes/brandx")
                .exchange().expectStatus().isOk()
                .expectBody()
                .jsonPath("$.inherited").isEqualTo(true)
                .jsonPath("$.theme.preset").isEqualTo("nord");
    }

    // ── boundary validation ─────────────────────────────────────────────

    @Test
    void anOutOfVocabularyRampIs400_notASilentlyWrongTheme() {
        asAdmin().put().uri("/bff/admin/themes/brandx").contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"preset\":\"nord\",\"ramp\":\"twilight\"}")
                .exchange().expectStatus().isBadRequest()
                .expectBody().jsonPath("$.fields.ramp").exists();
        verify(service, never()).set(any(), any(), anyString());
    }

    @Test
    void aMalformedColourIs400RatherThanA500FromTheCheckConstraint() {
        asAdmin().put().uri("/bff/admin/themes/brandx").contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"preset\":\"nord\",\"primaryHex\":\"fuchsia\"}")
                .exchange().expectStatus().isBadRequest()
                .expectBody().jsonPath("$.fields.primaryHex").exists();
        verify(service, never()).set(any(), any(), anyString());
    }

    @Test
    void aMissingPresetIs400() {
        asAdmin().put().uri("/bff/admin/themes/brandx").contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"ramp\":\"dusk\"}")
                .exchange().expectStatus().isBadRequest()
                .expectBody().jsonPath("$.fields.preset").exists();
        verify(service, never()).set(any(), any(), anyString());
    }

    @Test
    void anOmittedRampAndStyleAreAcceptedAndDefaulted() {
        when(service.set(any(DomainTheme.class), any(PrincipalDomain.class), anyString()))
                .thenReturn(Mono.just(row("brandx")));

        asAdmin().put().uri("/bff/admin/themes/brandx").contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"preset\":\"nord\"}")
                .exchange().expectStatus().isOk();

        verify(service).set(org.mockito.ArgumentMatchers.argThat(t ->
                        t.ramp().equals(DomainTheme.DEFAULT_RAMP)
                                && t.style().equals(DomainTheme.DEFAULT_STYLE)),
                any(PrincipalDomain.class), anyString());
    }

    @Test
    void listIsScopedByTheCallersOwnPrincipal() {
        when(service.list(any(PrincipalDomain.class)))
                .thenReturn(reactor.core.publisher.Flux.just(row("brandx")));

        asAdmin().get().uri("/bff/admin/themes")
                .exchange().expectStatus().isOk()
                .expectBody().jsonPath("$.themes[0].domain").isEqualTo("brandx");

        verify(service).list(any(PrincipalDomain.class));
    }
}
