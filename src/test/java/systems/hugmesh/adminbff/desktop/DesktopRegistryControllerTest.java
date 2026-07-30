package systems.hugmesh.adminbff.desktop;
import org.junit.jupiter.api.BeforeEach;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Nested;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.boot.webflux.test.autoconfigure.WebFluxTest;
import org.springframework.context.annotation.Import;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.reactive.server.WebTestClient;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import systems.hugmesh.adminbff.config.SecurityConfig;
import systems.hugmesh.commons.security.DomainRegistry;
import systems.hugmesh.commons.security.PrincipalDomain;
import systems.hugmesh.adminbff.web.ApiExceptionHandler;
import systems.hugmesh.adminbff.web.ValidationExceptionHandler;

import java.time.Instant;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.mockJwt;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.springSecurity;

/**
 * The DESKTOP DISCOVER REGISTRY controller role + fail-closed matrix — the acceptance bar for
 * the SECURITY KEYSTONE: discover-role gating, the domain-lock, the enabled-only allowlist,
 * and the no-cross-domain-leak deny.
 *
 * <p>Per the test-standard: USER-SITUATIONAL (each role's view), CROSS-USER (the isolation
 * boundary — a discover user of brand X cannot read brand Y / a disabled / absent ref), and
 * the explicit fail-closed cases (no domain claim, non-discover deny, cross-domain ref deny,
 * empty catalog serves nothing).
 */
@WebFluxTest(controllers = DesktopRegistryController.class)
@Import({SecurityConfig.class, DomainRegistry.class, ValidationExceptionHandler.class, ApiExceptionHandler.class})
class DesktopRegistryControllerTest {

    @Autowired ApplicationContext context;

    WebTestClient web;

    @BeforeEach
    void setUpWebTestClient() {
        web = WebTestClient.bindToApplicationContext(context).apply(springSecurity()).build();
    }

    @MockitoBean DesktopRegistryService registry;
    @MockitoBean ReactiveJwtDecoder jwtDecoder;

    /** The configured single-issuer (application.yml); a token from THIS issuer resolves to
     *  the "default" brand. A token from any OTHER issuer fails closed to NO_DOMAIN. */
    private static final String TRUSTED_ISSUER = "https://id.hugmesh.systems";

    // A discover user whose token comes from the TRUSTED issuer -> domain "default".
    private WebTestClient asDiscover() {
        return web.mutateWith(mockJwt().jwt(j -> j.issuer(TRUSTED_ISSUER)).authorities(
                new SimpleGrantedAuthority("ROLE_USER"), new SimpleGrantedAuthority("ROLE_DISCOVER")));
    }

    // A discover user whose token comes from an UNTRUSTED issuer -> NO_DOMAIN (fail-closed).
    private WebTestClient asDiscoverUntrustedIssuer() {
        return web.mutateWith(mockJwt().jwt(j -> j.issuer("https://evil.example")).authorities(
                new SimpleGrantedAuthority("ROLE_USER"), new SimpleGrantedAuthority("ROLE_DISCOVER")));
    }

    private WebTestClient asPlainUser() {
        return web.mutateWith(mockJwt().authorities(new SimpleGrantedAuthority("ROLE_USER")));
    }

    private WebTestClient asAdminNonDiscover() {
        return web.mutateWith(mockJwt().authorities(
                new SimpleGrantedAuthority("ROLE_USER"), new SimpleGrantedAuthority("ROLE_ADMIN")));
    }

    private static DesktopAppCatalogEntry enabledEntry() {
        return new DesktopAppCatalogEntry("c1", "org.mozilla.firefox", "Firefox",
                DesktopAppCatalogEntry.SOURCE_FLATPAK, true, "admin", "default", Instant.now(), null);
    }

    // ── USER-SITUATIONAL: discover user ALLOW ────────────────────────────────────

    @Nested
    class DiscoverUserAllow {
        @Test
        void index_asDiscover_servesEnabledRefs() {
            when(registry.listEnabled(eq("default"))).thenReturn(Flux.just(enabledEntry()));
            asDiscover().get().uri("/bff/desktop/registry")
                    .exchange().expectStatus().isOk()
                    .expectBody().jsonPath("$[0].appRef").isEqualTo("org.mozilla.firefox")
                    .jsonPath("$[0].enabled").isEqualTo(true);
            // the registry is consulted with the caller's locked (validated-issuer) domain.
            verify(registry).listEnabled("default");
        }

        @Test
        void ref_asDiscover_inEnabledAllowlist_isServed() {
            when(registry.fetchRef(eq("default"), eq("org.mozilla.firefox")))
                    .thenReturn(Mono.just("{\"ref\":\"org.mozilla.firefox\",\"dark\":true}"));
            asDiscover().get().uri("/bff/desktop/registry/refs/org.mozilla.firefox")
                    .exchange().expectStatus().isOk();
            verify(registry).fetchRef("default", "org.mozilla.firefox");
        }
    }

    // ── CROSS-USER / fail-closed DENY ────────────────────────────────────────────

    @Nested
    class FailClosedDeny {

        @Test
        void index_asPlainUser_nonDiscover_isForbidden_andNeverServes() {
            // non-discover -> registry deny (403); the service is never reached.
            asPlainUser().get().uri("/bff/desktop/registry")
                    .exchange().expectStatus().isForbidden();
            verify(registry, never()).listEnabled(anyString());
        }

        @Test
        void index_asAdminWithoutDiscover_isForbidden() {
            // an ADMIN role does NOT imply discover — fail-closed.
            asAdminNonDiscover().get().uri("/bff/desktop/registry")
                    .exchange().expectStatus().isForbidden();
            verify(registry, never()).listEnabled(anyString());
        }

        @Test
        void index_unauthenticated_isUnauthorized() {
            // no token at all -> 401 (the resource server rejects before the controller).
            web.get().uri("/bff/desktop/registry").exchange().expectStatus().isUnauthorized();
            verify(registry, never()).listEnabled(anyString());
        }

        @Test
        void ref_notInEnabledAllowlist_is404_noLeak() {
            // cross-domain ref / disabled ref / absent ref -> the service returns empty -> 404
            // (deny, no cross-domain leak about whether another brand has it).
            when(registry.fetchRef(eq("default"), eq("com.other.brandapp"))).thenReturn(Mono.empty());
            asDiscover().get().uri("/bff/desktop/registry/refs/com.other.brandapp")
                    .exchange().expectStatus().isNotFound();
            verify(registry).fetchRef("default", "com.other.brandapp");
        }

        @Test
        void index_emptyCatalog_servesNothing() {
            // empty / all-disabled catalog -> empty array (default-NONE), not an error.
            when(registry.listEnabled(eq("default"))).thenReturn(Flux.empty());
            asDiscover().get().uri("/bff/desktop/registry")
                    .exchange().expectStatus().isOk()
                    .expectBody().json("[]");
        }

        @Test
        void index_untrustedIssuer_noDomainClaim_servesNothing_failClosed() {
            // a discover user whose token comes from an UNTRUSTED issuer collapses to the
            // NO_DOMAIN sentinel -> the registry is asked for a domain that matches NO real
            // brand's rows, so it serves NOTHING (fail-closed; no domain claim -> deny).
            when(registry.listEnabled(eq(PrincipalDomain.NO_DOMAIN))).thenReturn(Flux.empty());
            asDiscoverUntrustedIssuer().get().uri("/bff/desktop/registry")
                    .exchange().expectStatus().isOk()
                    .expectBody().json("[]");
            verify(registry).listEnabled(PrincipalDomain.NO_DOMAIN);
        }
    }
}
