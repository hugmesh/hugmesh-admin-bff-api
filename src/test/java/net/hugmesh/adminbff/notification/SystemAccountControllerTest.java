package net.hugmesh.adminbff.notification;
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
import reactor.core.publisher.Mono;
import net.hugmesh.adminbff.config.SecurityConfig;
import net.hugmesh.commons.security.DomainRegistry;
import net.hugmesh.adminbff.web.ApiExceptionHandler;
import net.hugmesh.adminbff.web.ValidationExceptionHandler;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.mockJwt;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.springSecurity;

/**
 * The {@code @system}-account controller role matrix — the acceptance bar for the
 * SUPERADMIN-ONLY boundary on {@code POST /bff/admin/system-account/{domain}/provision}
 * (Notifications PR3). Mirrors {@code DomainRegistryControllerTest}: {@code @WebFluxTest}
 * + the real {@link SecurityConfig} so BOTH the coarse path gate
 * ({@code hasAnyRole ADMIN,SUPERADMIN}) AND the per-method
 * {@code @PreAuthorize("hasRole('SUPERADMIN')")} run.
 *
 * <ul>
 *   <li>SUPERADMIN — ALLOW (provisioning is cross-domain infra).</li>
 *   <li>ADMIN — DENY (403): passes the coarse gate, walled at the per-method SUPERADMIN
 *       gate, and NEVER reaches the provisioner.</li>
 *   <li>MOD / USER — DENY (403): never clear the coarse gate.</li>
 * </ul>
 */
@WebFluxTest(controllers = SystemAccountController.class)
@Import({SecurityConfig.class, DomainRegistry.class, ValidationExceptionHandler.class, ApiExceptionHandler.class})
class SystemAccountControllerTest {

    @Autowired ApplicationContext context;

    WebTestClient web;

    @BeforeEach
    void setUpWebTestClient() {
        web = WebTestClient.bindToApplicationContext(context).apply(springSecurity()).build();
    }

    @MockitoBean SystemAccountProvisioner provisioner;
    @MockitoBean ReactiveJwtDecoder jwtDecoder;

    private static final String SUBJECT = "superadmin-subject-7";
    private static final String URI = "/bff/admin/system-account/acme.test/provision";

    private WebTestClient asSuperadmin() {
        return web.mutateWith(mockJwt()
                .jwt(j -> j.subject(SUBJECT))
                .authorities(new SimpleGrantedAuthority("ROLE_USER"),
                        new SimpleGrantedAuthority("ROLE_SUPERADMIN")));
    }

    private WebTestClient asAdmin() {
        return web.mutateWith(mockJwt().authorities(
                new SimpleGrantedAuthority("ROLE_USER"), new SimpleGrantedAuthority("ROLE_ADMIN")));
    }

    private WebTestClient asMod() {
        return web.mutateWith(mockJwt().authorities(
                new SimpleGrantedAuthority("ROLE_USER"), new SimpleGrantedAuthority("ROLE_MOD")));
    }

    private WebTestClient asUser() {
        return web.mutateWith(mockJwt().authorities(new SimpleGrantedAuthority("ROLE_USER")));
    }

    // ── SUPERADMIN ALLOW ────────────────────────────────────────────────────────

    @Test
    void provision_asSuperadmin_isAllowed_andReturnsLeastPrivilegeRoles() {
        when(provisioner.provision("acme.test")).thenReturn(Mono.empty());
        when(provisioner.enabled()).thenReturn(true);
        asSuperadmin().post().uri(URI)
                .exchange().expectStatus().isOk()
                .expectBody()
                .jsonPath("$.domain").isEqualTo("acme.test")
                .jsonPath("$.handle").isEqualTo("system")
                .jsonPath("$.email").isEqualTo("system@acme.test")
                .jsonPath("$.provisioned").isEqualTo(true)
                // The response advertises the EXACT least-privilege role set — never admin.
                .jsonPath("$.roles[0]").isEqualTo("user")
                .jsonPath("$.roles[1]").isEqualTo("matrix")
                .jsonPath("$.roles[2]").isEqualTo("mastodon");
        verify(provisioner).provision("acme.test");
    }

    @Test
    void provision_asSuperadmin_shipsDark_reportsProvisionedFalse() {
        // SHIPS DARK: provisioner.enabled()==false → 200 with provisioned:false (no error).
        when(provisioner.provision("acme.test")).thenReturn(Mono.empty());
        when(provisioner.enabled()).thenReturn(false);
        asSuperadmin().post().uri(URI)
                .exchange().expectStatus().isOk()
                .expectBody().jsonPath("$.provisioned").isEqualTo(false);
        verify(provisioner).provision("acme.test");
    }

    // ── ADMIN DENY (403) + never reaches the provisioner ────────────────────────

    @Test
    void provision_asAdmin_isForbidden_andNeverProvisions() {
        asAdmin().post().uri(URI).exchange().expectStatus().isForbidden();
        verify(provisioner, never()).provision(anyString());
    }

    // ── MOD DENY (403) ──────────────────────────────────────────────────────────

    @Test
    void provision_asMod_isForbidden_andNeverProvisions() {
        asMod().post().uri(URI).exchange().expectStatus().isForbidden();
        verify(provisioner, never()).provision(anyString());
    }

    // ── USER DENY (403) ─────────────────────────────────────────────────────────

    @Test
    void provision_asUser_isForbidden_andNeverProvisions() {
        asUser().post().uri(URI).exchange().expectStatus().isForbidden();
        verify(provisioner, never()).provision(anyString());
    }
}
