package systems.hugmesh.adminbff.config;
import org.junit.jupiter.api.BeforeEach;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.boot.webflux.test.autoconfigure.WebFluxTest;
import org.springframework.context.annotation.Import;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.mockJwt;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.springSecurity;

/**
 * Stand-in controller exposing one endpoint per policy tier so the WebFlux
 * SecurityConfig path-matcher rules are exercised in isolation.
 */
@RestController
class Probes {
    @GetMapping("/actuator/health") String health() { return "UP"; }
    @GetMapping("/actuator/info") String info() { return "info"; }
    @PostMapping("/bff/login") String login() { return "ok"; }
    @PostMapping("/bff/register/google") String register() { return "ok"; }
    @GetMapping("/bff/admin/allowlist") String admin() { return "ok"; }
    // Stand-in for the in-UI SSH-terminal LIVE-transport WebSocket route
    // (/bff/admin/device-terminal/{deviceId}). The real route is a HandlerMapping-registered
    // WebSocket handler, not a controller, but its ONLY role wall is the /bff/admin/** path matcher
    // in SecurityConfig — so a GET stand-in on the same path proves the filter chain refuses
    // MOD/USER/anonymous BEFORE the handshake ever reaches the handler.
    @GetMapping("/bff/admin/device-terminal/dev-1") String deviceTerminal() { return "ok"; }
    @GetMapping("/bff/superadmin/service-store/acme.test") String superadmin() { return "ok"; }
    @GetMapping("/bff/public/announcements/login") String publicLogin() { return "ok"; }
    @GetMapping("/bff/announcements/home") String announcementsHome() { return "ok"; }
    @GetMapping("/bff/me") String me() { return "ok"; }
    // Stand-in for the springdoc-served OpenAPI spec path. The real handler is
    // contributed by springdoc-openapi-starter-webflux-ui; here we just need a
    // /v3/api-docs route so the SPEC_PATHS matcher can be exercised in isolation.
    @GetMapping("/v3/api-docs") String apiDocs() { return "{}"; }
}

/**
 * Integration test for the reactive {@link SecurityConfig} path rules, driven via
 * {@link WebTestClient} with {@code mockJwt()} synthetic authentications.
 *
 * <ul>
 *   <li>{@code /actuator/health} + {@code /actuator/info} — public.</li>
 *   <li>POST {@code /bff/login} + {@code /bff/register/**} — public (pre-auth).</li>
 *   <li>{@code /bff/admin/**} — ROLE_ADMIN.</li>
 *   <li>anything else ({@code /bff/me}) — merely authenticated.</li>
 * </ul>
 */
@WebFluxTest(controllers = Probes.class)
@Import({SecurityConfig.class, systems.hugmesh.commons.security.DomainRegistry.class})
class SecurityConfigPathRulesTest {

    @Autowired ApplicationContext context;

    WebTestClient client;

    @BeforeEach
    void setUpWebTestClient() {
        client = WebTestClient.bindToApplicationContext(context).apply(springSecurity()).build();
    }

    @MockitoBean ReactiveJwtDecoder jwtDecoder;

    @Test
    void health_isPublic() {
        client.get().uri("/actuator/health").exchange().expectStatus().isOk();
    }

    @Test
    void info_isPublic() {
        client.get().uri("/actuator/info").exchange().expectStatus().isOk();
    }

    @Test
    void login_isPublic() {
        client.post().uri("/bff/login").exchange().expectStatus().isOk();
    }

    @Test
    void register_isPublic() {
        client.post().uri("/bff/register/google").exchange().expectStatus().isOk();
    }

    @Test
    void admin_deniedForAnonymous() {
        client.get().uri("/bff/admin/allowlist").exchange().expectStatus().isUnauthorized();
    }

    @Test
    void admin_deniedForPlainUser() {
        client.mutateWith(mockJwt().authorities(authorities("ROLE_USER")))
                .get().uri("/bff/admin/allowlist").exchange().expectStatus().isForbidden();
    }

    @Test
    void admin_allowedForAdmin() {
        client.mutateWith(mockJwt().authorities(authorities("ROLE_USER", "ROLE_ADMIN")))
                .get().uri("/bff/admin/allowlist").exchange().expectStatus().isOk();
    }

    @Test
    void admin_allowedForSuperadmin() {
        // SUPERADMIN is a strict superset of ADMIN — it reaches the coarse /bff/admin
        // gate (cross-domain infra control plane). The per-row DOMAIN scoping is
        // applied downstream, not at this path matcher.
        client.mutateWith(mockJwt().authorities(authorities("ROLE_USER", "ROLE_SUPERADMIN")))
                .get().uri("/bff/admin/allowlist").exchange().expectStatus().isOk();
    }

    @Test
    void admin_deniedForMod() {
        // ROLE_MOD is a documented SIBLING of ROLE_ADMIN (no ADMIN>MOD edge), so a mod
        // never reaches the admin gate.
        client.mutateWith(mockJwt().authorities(authorities("ROLE_USER", "ROLE_MOD")))
                .get().uri("/bff/admin/allowlist").exchange().expectStatus().isForbidden();
    }

    // --- device-terminal WS route: the /bff/admin/** wall is its ONLY role gate ---
    // Handshake-level regression coverage that MOD/USER/anonymous are refused at the filter chain
    // on /bff/admin/device-terminal/** before the WebSocket handler runs.

    @Test
    void deviceTerminal_deniedForAnonymous() {
        client.get().uri("/bff/admin/device-terminal/dev-1")
                .exchange().expectStatus().isUnauthorized();
    }

    @Test
    void deviceTerminal_deniedForPlainUser() {
        client.mutateWith(mockJwt().authorities(authorities("ROLE_USER")))
                .get().uri("/bff/admin/device-terminal/dev-1").exchange().expectStatus().isForbidden();
    }

    @Test
    void deviceTerminal_deniedForMod() {
        client.mutateWith(mockJwt().authorities(authorities("ROLE_USER", "ROLE_MOD")))
                .get().uri("/bff/admin/device-terminal/dev-1").exchange().expectStatus().isForbidden();
    }

    @Test
    void deviceTerminal_reachableForAdmin() {
        // ADMIN clears the coarse wall (the deeper license/step-up/feature gates live in the handler).
        client.mutateWith(mockJwt().authorities(authorities("ROLE_USER", "ROLE_ADMIN")))
                .get().uri("/bff/admin/device-terminal/dev-1").exchange().expectStatus().isOk();
    }

    @Test
    void deviceTerminal_reachableForSuperadmin() {
        client.mutateWith(mockJwt().authorities(authorities("ROLE_USER", "ROLE_SUPERADMIN")))
                .get().uri("/bff/admin/device-terminal/dev-1").exchange().expectStatus().isOk();
    }

    // --- /bff/superadmin/** coarse gate: SUPERADMIN-ONLY (App-Store control plane) ---

    @Test
    void superadmin_deniedForAnonymous() {
        client.get().uri("/bff/superadmin/service-store/acme.test")
                .exchange().expectStatus().isUnauthorized();
    }

    @Test
    void superadmin_deniedForPlainUser() {
        client.mutateWith(mockJwt().authorities(authorities("ROLE_USER")))
                .get().uri("/bff/superadmin/service-store/acme.test")
                .exchange().expectStatus().isForbidden();
    }

    @Test
    void superadmin_deniedForAdmin() {
        // ADMIN clears /bff/admin/** but is walled off the SUPERADMIN-only control plane.
        client.mutateWith(mockJwt().authorities(authorities("ROLE_USER", "ROLE_ADMIN")))
                .get().uri("/bff/superadmin/service-store/acme.test")
                .exchange().expectStatus().isForbidden();
    }

    @Test
    void superadmin_deniedForMod() {
        client.mutateWith(mockJwt().authorities(authorities("ROLE_USER", "ROLE_MOD")))
                .get().uri("/bff/superadmin/service-store/acme.test")
                .exchange().expectStatus().isForbidden();
    }

    @Test
    void superadmin_allowedForSuperadmin() {
        client.mutateWith(mockJwt().authorities(authorities("ROLE_USER", "ROLE_SUPERADMIN")))
                .get().uri("/bff/superadmin/service-store/acme.test")
                .exchange().expectStatus().isOk();
    }

    @Test
    void publicAnnouncementsLogin_isPublic() {
        client.get().uri("/bff/public/announcements/login").exchange().expectStatus().isOk();
    }

    @Test
    void announcementsHome_deniedForAnonymous() {
        client.get().uri("/bff/announcements/home").exchange().expectStatus().isUnauthorized();
    }

    @Test
    void announcementsHome_allowedForAnyAuthenticatedUser() {
        client.mutateWith(mockJwt().authorities(authorities("ROLE_USER")))
                .get().uri("/bff/announcements/home").exchange().expectStatus().isOk();
    }

    @Test
    void me_deniedForAnonymous() {
        client.get().uri("/bff/me").exchange().expectStatus().isUnauthorized();
    }

    @Test
    void me_allowedForAnyAuthenticatedUser() {
        client.mutateWith(mockJwt().authorities(authorities("ROLE_USER")))
                .get().uri("/bff/me").exchange().expectStatus().isOk();
    }

    // --- OpenAPI spec gating (prod / default profile = neither dev nor test) ---
    // With no active profile the `!dev & !test` (prod) filter chain loads, so the
    // springdoc spec path requires ROLE_ADMIN — never publicly reachable.

    @Test
    void apiDocs_deniedForAnonymous_inProd() {
        client.get().uri("/v3/api-docs").exchange().expectStatus().isUnauthorized();
    }

    @Test
    void apiDocs_deniedForPlainUser_inProd() {
        client.mutateWith(mockJwt().authorities(authorities("ROLE_USER")))
                .get().uri("/v3/api-docs").exchange().expectStatus().isForbidden();
    }

    @Test
    void apiDocs_allowedForAdmin_inProd() {
        client.mutateWith(mockJwt().authorities(authorities("ROLE_USER", "ROLE_ADMIN")))
                .get().uri("/v3/api-docs").exchange().expectStatus().isOk();
    }

    private static Collection<GrantedAuthority> authorities(String... names) {
        List<GrantedAuthority> out = new ArrayList<>();
        for (String n : names) out.add(new SimpleGrantedAuthority(n));
        return out;
    }
}
