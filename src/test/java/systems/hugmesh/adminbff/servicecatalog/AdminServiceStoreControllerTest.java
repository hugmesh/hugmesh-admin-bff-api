package systems.hugmesh.adminbff.servicecatalog;
import org.junit.jupiter.api.BeforeEach;

import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.boot.webflux.test.autoconfigure.WebFluxTest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.reactive.server.WebTestClient;
import reactor.core.publisher.Flux;
import systems.hugmesh.adminbff.config.SecurityConfig;
import systems.hugmesh.commons.security.DomainRegistry;
import systems.hugmesh.commons.security.PrincipalDomain;
import systems.hugmesh.adminbff.web.ApiExceptionHandler;
import systems.hugmesh.adminbff.web.ValidationExceptionHandler;

import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.mockJwt;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.springSecurity;

/**
 * The BOTTOM tier of the two-tier curation — {@code GET /bff/admin/service-store}. Proves:
 * <ul>
 *   <li>the surface is reachable by ADMIN and SUPERADMIN, but MOD/USER → 403 (the
 *       {@code /bff/admin/**} coarse gate);</li>
 *   <li>the {@link PrincipalDomain} the controller threads to the service is resolved from the
 *       CRYPTOGRAPHICALLY-VALIDATED JWT ISSUER (not a request field) — a brand-X admin's
 *       call resolves domain {@code brandx}, a brand-Y admin's resolves {@code brandy}, so
 *       a brand-X admin can NEVER pull brand-Y's catalog; SUPERADMIN resolves UNSCOPED.</li>
 * </ul>
 * A two-issuer {@link DomainRegistry} is wired so the issuer maps to a real domain.
 */
@WebFluxTest(controllers = AdminServiceStoreController.class)
@Import({SecurityConfig.class, ValidationExceptionHandler.class, ApiExceptionHandler.class,
        AdminServiceStoreControllerTest.TwoIssuerRegistry.class})
class AdminServiceStoreControllerTest {

    @Autowired ApplicationContext context;

    WebTestClient web;

    @BeforeEach
    void setUpWebTestClient() {
        web = WebTestClient.bindToApplicationContext(context).apply(springSecurity()).build();
    }

    @MockitoBean ServiceCurationService service;
    @MockitoBean ReactiveJwtDecoder jwtDecoder;

    static final String BRANDX = "https://idp.brandx.example";
    static final String BRANDY = "https://idp.brandy.example";

    /** A two-brand registry so the validated issuer maps to a real domain. Replaces the
     *  single-issuer default {@link DomainRegistry} the SecurityConfig would otherwise wire. */
    static class TwoIssuerRegistry {
        @Bean
        DomainRegistry domainRegistry() {
            return new DomainRegistry("",
                    BRANDX + "=brandx," + BRANDY + "=brandy");
        }
    }

    private WebTestClient adminOf(String issuer) {
        return web.mutateWith(mockJwt()
                .jwt(j -> j.issuer(issuer).claim("roles", java.util.List.of("admin")))
                .authorities(new SimpleGrantedAuthority("ROLE_USER"),
                        new SimpleGrantedAuthority("ROLE_ADMIN")));
    }

    private WebTestClient superadminOf(String issuer) {
        return web.mutateWith(mockJwt()
                .jwt(j -> j.issuer(issuer).claim("roles", java.util.List.of("superadmin")))
                .authorities(new SimpleGrantedAuthority("ROLE_USER"),
                        new SimpleGrantedAuthority("ROLE_SUPERADMIN")));
    }

    private WebTestClient modOf(String issuer) {
        return web.mutateWith(mockJwt()
                .jwt(j -> j.issuer(issuer))
                .authorities(new SimpleGrantedAuthority("ROLE_USER"),
                        new SimpleGrantedAuthority("ROLE_MOD")));
    }

    private WebTestClient plainUser() {
        return web.mutateWith(mockJwt().authorities(new SimpleGrantedAuthority("ROLE_USER")));
    }

    private static ServiceCuration row(String domain, String key) {
        return new ServiceCuration("c", domain, key, ServiceCuration.STATE_OFFERED, "root",
                Instant.now(), Instant.now());
    }

    // ── ADMIN read resolves the OWN-domain scope from the validated issuer ───────

    @Test
    void brandXAdmin_resolvesScopeBrandx_andSeesOnlyOfferedRows() {
        when(service.offeredCatalog(any())).thenReturn(Flux.just(row("brandx", "owncast")));

        adminOf(BRANDX).get().uri("/bff/admin/service-store")
                .exchange().expectStatus().isOk()
                .expectBody().jsonPath("$[0].domain").isEqualTo("brandx");

        ArgumentCaptor<PrincipalDomain> cap = ArgumentCaptor.forClass(PrincipalDomain.class);
        verify(service).offeredCatalog(cap.capture());
        // The scope passed to the service is brandx (from the issuer), SCOPED (not superadmin).
        assertThat(cap.getValue().domain()).isEqualTo("brandx");
        assertThat(cap.getValue().scoped()).isTrue();
    }

    @Test
    void brandYAdmin_resolvesScopeBrandy() {
        when(service.offeredCatalog(any())).thenReturn(Flux.just(row("brandy", "akkoma")));

        adminOf(BRANDY).get().uri("/bff/admin/service-store")
                .exchange().expectStatus().isOk()
                .expectBody().jsonPath("$[0].domain").isEqualTo("brandy");

        ArgumentCaptor<PrincipalDomain> cap = ArgumentCaptor.forClass(PrincipalDomain.class);
        verify(service).offeredCatalog(cap.capture());
        // A brand-Y admin resolves brandy — it can never be brandx (no cross-domain read).
        assertThat(cap.getValue().domain()).isEqualTo("brandy");
        assertThat(cap.getValue().domain()).isNotEqualTo("brandx");
        assertThat(cap.getValue().scoped()).isTrue();
    }

    @Test
    void superadmin_resolvesUnscoped() {
        when(service.offeredCatalog(any())).thenReturn(Flux.empty());

        superadminOf(BRANDX).get().uri("/bff/admin/service-store")
                .exchange().expectStatus().isOk();

        ArgumentCaptor<PrincipalDomain> cap = ArgumentCaptor.forClass(PrincipalDomain.class);
        verify(service).offeredCatalog(cap.capture());
        // SUPERADMIN is UNSCOPED (sees all brands' offered rows).
        assertThat(cap.getValue().scoped()).isFalse();
        assertThat(cap.getValue().superadmin()).isTrue();
    }

    // ── MOD / USER are walled at the coarse /bff/admin/** gate ───────────────────

    @Test
    void mod_isForbidden_andNeverReachesService() {
        modOf(BRANDX).get().uri("/bff/admin/service-store")
                .exchange().expectStatus().isForbidden();
        verify(service, never()).offeredCatalog(any());
    }

    @Test
    void user_isForbidden_andNeverReachesService() {
        plainUser().get().uri("/bff/admin/service-store")
                .exchange().expectStatus().isForbidden();
        verify(service, never()).offeredCatalog(any());
    }

    @Test
    void anonymous_isUnauthorized() {
        web.get().uri("/bff/admin/service-store").exchange().expectStatus().isUnauthorized();
    }
}
