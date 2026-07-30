package systems.hugmesh.adminbff.platform;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.boot.webflux.test.autoconfigure.WebFluxTest;
import org.springframework.context.annotation.Import;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.reactive.server.WebTestClient;
import reactor.core.publisher.Flux;
import systems.hugmesh.adminbff.config.SecurityConfig;
import systems.hugmesh.adminbff.iso.IsoArtifact;
import systems.hugmesh.adminbff.iso.IsoRepository;
import systems.hugmesh.commons.security.DomainRegistry;
import systems.hugmesh.adminbff.web.ApiExceptionHandler;
import systems.hugmesh.adminbff.web.ValidationExceptionHandler;

import java.util.List;

import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.mockJwt;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.springSecurity;

/**
 * The AUTHZ acceptance bar for {@code GET /bff/admin/platform-capabilities}. {@code @WebFluxTest} +
 * the real {@link SecurityConfig} so BOTH the coarse {@code /bff/admin/**} path gate AND the
 * per-method {@code @PreAuthorize("hasAnyRole('ADMIN','SUPERADMIN')")} run:
 *
 * <ul>
 *   <li>ADMIN / SUPERADMIN — 200 with a well-formed envelope.</li>
 *   <li>MOD / USER — 403 + the probe is never consulted (DENY).</li>
 *   <li>unauthenticated — 401.</li>
 * </ul>
 *
 * <p>Data/flag/fail-safe REFLECTION is covered by the standalone
 * {@link PlatformCapabilitiesControllerDataTest} (a fresh controller per case, so the per-instance
 * TTL cache cannot leak one case's reading into another — the {@code @WebFluxTest} controller is a
 * shared singleton, so a common stub is set in {@link #setUp()} and only authz is asserted here).
 */
@WebFluxTest(controllers = PlatformCapabilitiesController.class)
@Import({SecurityConfig.class, DomainRegistry.class, ValidationExceptionHandler.class, ApiExceptionHandler.class})
class PlatformCapabilitiesControllerTest {

    @Autowired ApplicationContext context;

    WebTestClient web;

    @MockitoBean PlatformCapabilityProbe probe;
    @MockitoBean IsoRepository isoRepository;
    @MockitoBean ReactiveJwtDecoder jwtDecoder;

    @BeforeEach
    void setUp() {
        web = WebTestClient.bindToApplicationContext(context).apply(springSecurity()).build();
        when(probe.probe()).thenReturn(
                new PlatformCapabilityProbe.Result(true, true, true, List.of()));
        when(isoRepository.list()).thenReturn(Flux.just(new IsoArtifact("pi.img", "https://x/pi.img")));
    }

    private WebTestClient asAdmin() {
        return web.mutateWith(mockJwt().authorities(
                new SimpleGrantedAuthority("ROLE_USER"), new SimpleGrantedAuthority("ROLE_ADMIN")));
    }

    private WebTestClient asSuperadmin() {
        return web.mutateWith(mockJwt().authorities(
                new SimpleGrantedAuthority("ROLE_USER"), new SimpleGrantedAuthority("ROLE_SUPERADMIN")));
    }

    private WebTestClient asMod() {
        return web.mutateWith(mockJwt().authorities(
                new SimpleGrantedAuthority("ROLE_USER"), new SimpleGrantedAuthority("ROLE_MOD")));
    }

    private WebTestClient asUser() {
        return web.mutateWith(mockJwt().authorities(new SimpleGrantedAuthority("ROLE_USER")));
    }

    @Test
    void asAdmin_isOk_withWellFormedEnvelope() {
        asAdmin().get().uri("/bff/admin/platform-capabilities")
                .exchange().expectStatus().isOk()
                .expectBody()
                .jsonPath("$.argocdPresent").exists()
                .jsonPath("$.veleroPresent").exists()
                .jsonPath("$.buildNodePresent").exists()
                .jsonPath("$.imagesGenerated").exists()
                .jsonPath("$.anubisEnabled").exists()
                .jsonPath("$.warnings").isArray();
    }

    @Test
    void asSuperadmin_isOk() {
        asSuperadmin().get().uri("/bff/admin/platform-capabilities")
                .exchange().expectStatus().isOk();
    }

    @Test
    void asMod_isForbidden_andProbeNeverConsulted() {
        asMod().get().uri("/bff/admin/platform-capabilities")
                .exchange().expectStatus().isForbidden();
        verify(probe, never()).probe();
    }

    @Test
    void asUser_isForbidden_andProbeNeverConsulted() {
        asUser().get().uri("/bff/admin/platform-capabilities")
                .exchange().expectStatus().isForbidden();
        verify(probe, never()).probe();
    }

    @Test
    void unauthenticated_is401() {
        web.get().uri("/bff/admin/platform-capabilities")
                .exchange().expectStatus().isUnauthorized();
        verify(probe, never()).probe();
    }
}
