package net.hugmesh.adminbff.config;
import org.junit.jupiter.api.BeforeEach;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.boot.webflux.test.autoconfigure.WebFluxTest;
import org.springframework.context.annotation.Import;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.mockJwt;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.springSecurity;

/**
 * Stand-in for a real admin controller (top-level so {@code @WebFluxTest} registers it as a
 * route): the path is under {@code /bff/admin/**} / {@code /bff/superadmin/**} (so the coarse
 * gate admits the right roles) AND the method carries {@code @PreAuthorize}, exactly like the
 * 60+ production endpoints.
 */
@RestController
class Guarded {
    // Reactive return types — reactive method security (@EnableReactiveMethodSecurity)
    // proxies these @PreAuthorize methods and expects a Publisher, like the real controllers.
    @PreAuthorize("hasRole('ADMIN')")
    @GetMapping("/bff/admin/guarded-admin")
    reactor.core.publisher.Mono<String> adminOnly() { return reactor.core.publisher.Mono.just("ok"); }

    @PreAuthorize("hasRole('SUPERADMIN')")
    @GetMapping("/bff/superadmin/guarded-super")
    reactor.core.publisher.Mono<String> superadminOnly() { return reactor.core.publisher.Mono.just("ok"); }
}

/**
 * The V3 SUPERADMIN-BYPASS matrix at the METHOD-SECURITY layer — the sharpest V3 edge. The
 * coarse {@code /bff/admin/**} path matcher already admits SUPERADMIN (see
 * {@link SecurityConfigPathRulesTest}); this test proves the {@code @PreAuthorize("hasRole
 * ('ADMIN')")} method gate ALSO admits SUPERADMIN — i.e. the {@link SecurityConfig#roleHierarchy()}
 * ({@code ROLE_SUPERADMIN > ROLE_ADMIN}) is actually wired into the
 * {@code adminMethodSecurityExpressionHandler}, so the 60+ {@code hasRole('ADMIN')} methods do
 * NOT 403 a superadmin AFTER it clears the path gate. Without the hierarchy this would be the
 * documented V3 hole (SUPERADMIN passes the path, then the method denies).
 *
 * <p>Driven against a stand-in controller carrying the SAME annotations the real admin
 * controllers carry, with the REAL {@link SecurityConfig} imported (so the production
 * RoleHierarchy + expression handler are exercised). The matrix:
 * <ul>
 *   <li>{@code hasRole('ADMIN')} method: ADMIN ALLOW, SUPERADMIN ALLOW (hierarchy), MOD/USER DENY;</li>
 *   <li>{@code hasRole('SUPERADMIN')} method: SUPERADMIN ALLOW, ADMIN/MOD/USER DENY (no edge up).</li>
 * </ul>
 */
@WebFluxTest(controllers = Guarded.class)
@Import({SecurityConfig.class, net.hugmesh.commons.security.DomainRegistry.class})
class MethodSecuritySuperadminBypassTest {

    @Autowired ApplicationContext context;

    WebTestClient client;

    @BeforeEach
    void setUpWebTestClient() {
        client = WebTestClient.bindToApplicationContext(context).apply(springSecurity()).build();
    }
    @MockitoBean ReactiveJwtDecoder jwtDecoder;

    private WebTestClient as(String... roles) {
        return client.mutateWith(mockJwt().authorities(authorities(roles)));
    }

    // ── hasRole('ADMIN') method: SUPERADMIN must be ALLOWED via the hierarchy ──
    @Test
    void adminMethod_allowsAdmin() {
        as("ROLE_USER", "ROLE_ADMIN").get().uri("/bff/admin/guarded-admin")
                .exchange().expectStatus().isOk();
    }

    @Test
    void adminMethod_allowsSuperadmin_viaRoleHierarchy() {
        // The load-bearing V3 assertion: a SUPERADMIN (no explicit ROLE_ADMIN) clears a
        // hasRole('ADMIN') METHOD gate because ROLE_SUPERADMIN > ROLE_ADMIN.
        as("ROLE_USER", "ROLE_SUPERADMIN").get().uri("/bff/admin/guarded-admin")
                .exchange().expectStatus().isOk();
    }

    @Test
    void adminMethod_deniesMod() {
        as("ROLE_USER", "ROLE_MOD").get().uri("/bff/admin/guarded-admin")
                .exchange().expectStatus().isForbidden();
    }

    @Test
    void adminMethod_deniesPlainUser() {
        as("ROLE_USER").get().uri("/bff/admin/guarded-admin")
                .exchange().expectStatus().isForbidden();
    }

    // ── hasRole('SUPERADMIN') method: only SUPERADMIN (no edge up from ADMIN) ──
    @Test
    void superadminMethod_allowsSuperadmin() {
        as("ROLE_USER", "ROLE_SUPERADMIN").get().uri("/bff/superadmin/guarded-super")
                .exchange().expectStatus().isOk();
    }

    @Test
    void superadminMethod_deniesAdmin() {
        // ADMIN is NOT a superset of SUPERADMIN — the hierarchy has no ADMIN>SUPERADMIN edge.
        as("ROLE_USER", "ROLE_ADMIN").get().uri("/bff/superadmin/guarded-super")
                .exchange().expectStatus().isForbidden();
    }

    @Test
    void superadminMethod_deniesUser() {
        as("ROLE_USER").get().uri("/bff/superadmin/guarded-super")
                .exchange().expectStatus().isForbidden();
    }

    private static Collection<GrantedAuthority> authorities(String... names) {
        List<GrantedAuthority> out = new ArrayList<>();
        for (String n : names) out.add(new SimpleGrantedAuthority(n));
        return out;
    }
}
