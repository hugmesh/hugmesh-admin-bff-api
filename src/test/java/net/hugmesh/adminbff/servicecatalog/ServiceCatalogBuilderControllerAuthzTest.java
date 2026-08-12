package net.hugmesh.adminbff.servicecatalog;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webflux.test.autoconfigure.WebFluxTest;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Import;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.reactive.server.WebTestClient;
import net.hugmesh.adminbff.config.SecurityConfig;
import net.hugmesh.adminbff.platform.PlatformCapabilityProbe;
import net.hugmesh.commons.security.DomainRegistry;

import java.util.List;

import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.mockJwt;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.springSecurity;

/**
 * {@link ServiceCatalogBuilderController} — the SUPERADMIN-ONLY boundary on
 * {@code GET /bff/superadmin/service-store/builder}. {@code @WebFluxTest} + the real
 * {@link SecurityConfig} so BOTH the coarse {@code /bff/superadmin/**} gate AND the per-method
 * {@code @PreAuthorize("hasRole('SUPERADMIN')")} run. No {@link KanikoBuildLauncher} bean is
 * registered in this slice (mirrors the disabled-by-default production wiring); the capability
 * VALUES themselves are covered by {@link ServiceCatalogBuilderControllerTest}.
 */
@WebFluxTest(controllers = ServiceCatalogBuilderController.class)
@Import({SecurityConfig.class, DomainRegistry.class})
class ServiceCatalogBuilderControllerAuthzTest {

    @Autowired ApplicationContext context;

    WebTestClient web;

    @BeforeEach
    void setUpWebTestClient() {
        web = WebTestClient.bindToApplicationContext(context).apply(springSecurity()).build();
    }

    @MockitoBean PlatformCapabilityProbe capabilityProbe;
    @MockitoBean ReactiveJwtDecoder jwtDecoder;

    private WebTestClient asSuperadmin() {
        return web.mutateWith(mockJwt().authorities(new SimpleGrantedAuthority("ROLE_USER"),
                new SimpleGrantedAuthority("ROLE_SUPERADMIN")));
    }

    private WebTestClient asAdmin() {
        return web.mutateWith(mockJwt().authorities(
                new SimpleGrantedAuthority("ROLE_USER"), new SimpleGrantedAuthority("ROLE_ADMIN")));
    }

    @Test
    void asSuperadmin_isAllowed_noBuilderBeanInThisSlice_reportsDisabled() {
        when(capabilityProbe.probe())
                .thenReturn(new PlatformCapabilityProbe.Result(false, false, false, List.of()));
        asSuperadmin().get().uri("/bff/superadmin/service-store/builder")
                .exchange().expectStatus().isOk()
                .expectBody()
                .jsonPath("$.enabled").isEqualTo(false)
                .jsonPath("$.buildNodePresent").isEqualTo(false);
    }

    @Test
    void asAdmin_isForbidden_andNeverProbes() {
        asAdmin().get().uri("/bff/superadmin/service-store/builder")
                .exchange().expectStatus().isForbidden();
        verify(capabilityProbe, never()).probe();
    }

    @Test
    void anonymous_isUnauthorized() {
        web.get().uri("/bff/superadmin/service-store/builder")
                .exchange().expectStatus().isUnauthorized();
    }
}
