package net.hugmesh.adminbff.oidcprovider;
import org.junit.jupiter.api.BeforeEach;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.boot.webflux.test.autoconfigure.WebFluxTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.reactive.server.WebTestClient;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import net.hugmesh.adminbff.config.SecurityConfig;
import net.hugmesh.commons.security.DomainRegistry;
import net.hugmesh.adminbff.web.ApiExceptionHandler;
import net.hugmesh.adminbff.web.ValidationExceptionHandler;

import java.util.List;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.mockJwt;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.springSecurity;

/**
 * HTTP authorization + domain-scoping matrix for the previously ZERO-COVERAGE
 * {@link OidcProviderRolesController} ({@code /bff/admin/oidc-providers/**}: who may
 * READ / MUTATE which Casdoor roles new users auto-receive per OIDC provider). Driven
 * through the REAL {@link SecurityConfig} (the production {@code /bff/admin/** ->
 * hasRole('ADMIN','SUPERADMIN')} path gate + the role hierarchy + the per-method
 * {@code @PreAuthorize("hasRole('ADMIN')")}).
 *
 * <p>Two boundaries asserted:
 * <ol>
 *   <li><b>ROLE GATE</b> — ADMIN ALLOW; SUPERADMIN ALLOW (via {@code ROLE_SUPERADMIN >
 *       ROLE_ADMIN}); MOD/USER -&gt; 403; unauth -&gt; 401. The DENY tests
 *       {@code verify(repo, never())} so the guarded body provably never ran.
 *       <b>What this pins, exactly (measured 2026-09-17):</b> the COMBINED gate. Because the
 *       real {@code SecurityConfig} path rule ({@code /bff/admin/** ->
 *       hasAnyRole('ADMIN','SUPERADMIN')}, SecurityConfig.java:284) denies MOD/USER on its
 *       own, deleting all three {@code @PreAuthorize("hasRole('ADMIN')")} annotations from
 *       the controller leaves this class fully GREEN (19/19) — it detects the loss of both
 *       layers together, never of either one alone. The per-method layer is pinned
 *       SEPARATELY by {@link OidcProviderRolesMethodGateTest}, which runs the controller
 *       with a {@code permitAll} path chain; dropping any one annotation there turns it
 *       red.</li>
 *   <li><b>DOMAIN SCOPING from the VALIDATED ISSUER</b> — the {@code domain} the repo is
 *       queried/mutated with is derived from the token's cryptographically-validated
 *       {@code iss} (via {@link DomainRegistry}), NEVER a path/body/header. A brand-X admin
 *       reads/writes brand-X rows; a brand-Y admin reads/writes brand-Y rows; the two are
 *       isolated. This is captured by asserting the EXACT {@code domain} argument passed to
 *       the repo (MUTATION-RESISTANT: swap the scope source to a param and the captured
 *       domain stops tracking the issuer).</li>
 * </ol>
 *
 * <p>The principals carry a real per-brand {@code iss} on the mock JWT, and the registry
 * is the multi-issuer brand-X/brand-Y registry, so {@code PrincipalDomain.of(auth, registry)}
 * resolves the brand exactly as in production — no in-test domain is invented.
 */
@WebFluxTest(controllers = OidcProviderRolesController.class)
@Import({SecurityConfig.class, ValidationExceptionHandler.class, ApiExceptionHandler.class})
class OidcProviderRolesControllerAuthzTest {

    static final String BRANDX_ISS = "https://idp.brandx.example";
    static final String BRANDY_ISS = "https://idp.brandy.example";

    /** Multi-issuer registry so the validated iss resolves brandx / brandy (overrides the
     *  property-driven single-issuer bean the slice would otherwise create). */
    @TestConfiguration
    static class Registry {
        @Bean
        DomainRegistry domainRegistry() {
            return new DomainRegistry("", BRANDX_ISS + "=brandx," + BRANDY_ISS + "=brandy");
        }
    }

    @Autowired ApplicationContext context;

    WebTestClient web;

    @BeforeEach
    void setUpWebTestClient() {
        web = WebTestClient.bindToApplicationContext(context).apply(springSecurity()).build();
    }

    @MockitoBean OidcProviderRoleRepository repo;
    @MockitoBean ReactiveJwtDecoder jwtDecoder;

    private WebTestClient as(String issuer, String... roles) {
        SimpleGrantedAuthority[] auths = new SimpleGrantedAuthority[roles.length];
        for (int i = 0; i < roles.length; i++) auths[i] = new SimpleGrantedAuthority(roles[i]);
        return web.mutateWith(mockJwt()
                .jwt(j -> j.issuer(issuer).subject("subj").claim("roles", roleNamesOf(roles)))
                .authorities(auths));
    }

    private static List<String> roleNamesOf(String[] roles) {
        // Casdoor roles-claim shape so PrincipalDomain/Roles see the same role the authority does.
        return java.util.Arrays.stream(roles)
                .map(r -> r.startsWith("ROLE_") ? r.substring("ROLE_".length()).toLowerCase() : r.toLowerCase())
                .toList();
    }

    private WebTestClient adminOf(String issuer)      { return as(issuer, "ROLE_USER", "ROLE_ADMIN"); }
    private WebTestClient superadminOf(String issuer) { return as(issuer, "ROLE_USER", "ROLE_SUPERADMIN"); }
    private WebTestClient modOf(String issuer)        { return as(issuer, "ROLE_USER", "ROLE_MOD"); }
    private WebTestClient userOf(String issuer)       { return as(issuer, "ROLE_USER"); }

    // ════════════════════════ ROLE GATE — list (GET) ══════════════════════════════════

    @Test
    void listRoles_asAdmin_authorized_scopedToOwnDomain() {
        when(repo.listByDomain(eq("brandx"))).thenReturn(Flux.just(
                new OidcProviderRole("brandx", "google", "user", null)));
        adminOf(BRANDX_ISS).get().uri("/bff/admin/oidc-providers/roles")
                .exchange().expectStatus().isOk()
                .expectBody().jsonPath("$.providers[0].provider").isEqualTo("google");
        // domain comes from the VALIDATED issuer (brandx), not any request input.
        verify(repo).listByDomain(eq("brandx"));
    }

    @Test
    void listRoles_asSuperadmin_authorized() {
        when(repo.listByDomain(anyString())).thenReturn(Flux.empty());
        superadminOf(BRANDX_ISS).get().uri("/bff/admin/oidc-providers/roles")
                .exchange().expectStatus().isOk();
        verify(repo).listByDomain(anyString());
    }

    @Test
    void listRoles_asMod_isForbidden_andNeverReads() {
        modOf(BRANDX_ISS).get().uri("/bff/admin/oidc-providers/roles")
                .exchange().expectStatus().isForbidden();
        verify(repo, never()).listByDomain(anyString());
    }

    @Test
    void listRoles_asUser_isForbidden_andNeverReads() {
        userOf(BRANDX_ISS).get().uri("/bff/admin/oidc-providers/roles")
                .exchange().expectStatus().isForbidden();
        verify(repo, never()).listByDomain(anyString());
    }

    @Test
    void listRoles_unauthenticated_is401_andNeverReads() {
        web.get().uri("/bff/admin/oidc-providers/roles")
                .exchange().expectStatus().isUnauthorized();
        verify(repo, never()).listByDomain(anyString());
    }

    // ════════════════════════ ROLE GATE — set (PUT) ════════════════════════════════════

    @Test
    void setRoles_asAdmin_authorized_scopedToOwnDomain() {
        when(repo.replaceRoles(eq("brandx"), eq("google"), any())).thenReturn(Mono.empty());
        adminOf(BRANDX_ISS).put().uri("/bff/admin/oidc-providers/google/roles")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"roles\":[\"user\",\"mod\"]}")
                .exchange().expectStatus().isOk()
                .expectBody().jsonPath("$.domain").isEqualTo("brandx");
        verify(repo).replaceRoles(eq("brandx"), eq("google"), any());
    }

    @Test
    void setRoles_asMod_isForbidden_andNeverWrites() {
        modOf(BRANDX_ISS).put().uri("/bff/admin/oidc-providers/google/roles")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"roles\":[\"user\"]}")
                .exchange().expectStatus().isForbidden();
        verify(repo, never()).replaceRoles(anyString(), anyString(), any());
    }

    @Test
    void setRoles_asUser_isForbidden_andNeverWrites() {
        userOf(BRANDX_ISS).put().uri("/bff/admin/oidc-providers/google/roles")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"roles\":[\"user\"]}")
                .exchange().expectStatus().isForbidden();
        verify(repo, never()).replaceRoles(anyString(), anyString(), any());
    }

    @Test
    void setRoles_unauthenticated_is401_andNeverWrites() {
        web.put().uri("/bff/admin/oidc-providers/google/roles")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"roles\":[\"user\"]}")
                .exchange().expectStatus().isUnauthorized();
        verify(repo, never()).replaceRoles(anyString(), anyString(), any());
    }

    // ════════════════════════ ROLE GATE — clear (DELETE) ══════════════════════════════

    @Test
    void clearRoles_asAdmin_authorized_scopedToOwnDomain() {
        when(repo.clearRoles(eq("brandx"), eq("google"))).thenReturn(Mono.empty());
        adminOf(BRANDX_ISS).delete().uri("/bff/admin/oidc-providers/google/roles")
                .exchange().expectStatus().isOk();
        verify(repo).clearRoles(eq("brandx"), eq("google"));
    }

    @Test
    void clearRoles_asUser_isForbidden_andNeverClears() {
        userOf(BRANDX_ISS).delete().uri("/bff/admin/oidc-providers/google/roles")
                .exchange().expectStatus().isForbidden();
        verify(repo, never()).clearRoles(anyString(), anyString());
    }

    @Test
    void clearRoles_unauthenticated_is401_andNeverClears() {
        web.delete().uri("/bff/admin/oidc-providers/google/roles")
                .exchange().expectStatus().isUnauthorized();
        verify(repo, never()).clearRoles(anyString(), anyString());
    }

    // ════════════════════════ CROSS-DOMAIN ISOLATION (issuer-derived scope) ════════════

    @Test
    void listRoles_brandYAdmin_readsBrandYRows_notBrandX() {
        // A brand-Y admin's read is scoped to brandy purely from the validated iss — it can
        // NEVER read brand-X's provider-role mappings. CROSS-USER DENY (tenant isolation).
        when(repo.listByDomain(eq("brandy"))).thenReturn(Flux.empty());
        adminOf(BRANDY_ISS).get().uri("/bff/admin/oidc-providers/roles")
                .exchange().expectStatus().isOk();
        verify(repo).listByDomain(eq("brandy"));
        verify(repo, never()).listByDomain(eq("brandx"));
    }

    @Test
    void setRoles_brandYAdmin_writesBrandYRows_notBrandX() {
        // SECURITY: the mutation lands on brandy (issuer-derived), regardless of the path
        // provider segment or body — a brand-Y admin cannot write brand-X's mapping.
        when(repo.replaceRoles(eq("brandy"), eq("github"), any())).thenReturn(Mono.empty());
        adminOf(BRANDY_ISS).put().uri("/bff/admin/oidc-providers/github/roles")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"roles\":[\"user\"]}")
                .exchange().expectStatus().isOk()
                .expectBody().jsonPath("$.domain").isEqualTo("brandy");
        verify(repo).replaceRoles(eq("brandy"), eq("github"), any());
        verify(repo, never()).replaceRoles(eq("brandx"), anyString(), any());
    }

    // ════════════════════════ input validation (defense-in-depth) ═════════════════════

    @Test
    void setRoles_invalidProviderPathVar_isBadRequest_andNeverWrites() {
        // @Pattern("[A-Za-z0-9_-]+") on the provider path-var rejects a slash/dot injection.
        adminOf(BRANDX_ISS).put().uri("/bff/admin/oidc-providers/bad..provider/roles")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"roles\":[\"user\"]}")
                .exchange().expectStatus().isBadRequest();
        verify(repo, never()).replaceRoles(anyString(), anyString(), any());
    }

    @Test
    void setRoles_invalidRoleName_isBadRequest_andNeverWrites() {
        // @Pattern("[a-z0-9_-]+") on each role rejects an upper-cased / spaced role name.
        adminOf(BRANDX_ISS).put().uri("/bff/admin/oidc-providers/google/roles")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"roles\":[\"NOT VALID\"]}")
                .exchange().expectStatus().isBadRequest();
        verify(repo, never()).replaceRoles(anyString(), anyString(), any());
    }

    // ════════════ RESERVED-ROLE DENYLIST (privilege-escalation boundary) ═══════════════
    //
    // The OIDC default-role write is an INDIRECT grant channel: a role seeded here is later
    // applied verbatim to a first-login user. It must enforce the SAME non-grantable boundary
    // AdminController.grantRole does — a brand ADMIN must NOT be able to seed 'superadmin' (a
    // cross-tenant super-role) or a service / bootstrap role and self-escalate at first-login.

    @Test
    void setRoles_superadmin_isRejected_andNeverWrites() {
        // EXPLOIT (finding #1): brand ADMIN tries to seed 'superadmin' as a provider default.
        // Must be a 400 with the reserved-role error AND the repo must never be touched.
        adminOf(BRANDX_ISS).put().uri("/bff/admin/oidc-providers/google/roles")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"roles\":[\"user\",\"superadmin\"]}")
                .exchange().expectStatus().isBadRequest()
                .expectBody().jsonPath("$.error").value(org.hamcrest.Matchers.containsString("reserved"));
        verify(repo, never()).replaceRoles(anyString(), anyString(), any());
    }

    @Test
    void setRoles_serviceBootstrapRoles_areRejected_andNeverWrite() {
        // EXPLOIT (finding #8): service / bootstrap roles are equally non-grantable. The
        // hyphenated 'admin-api' must fold to the reserved ADMIN_API token and be rejected too.
        for (String reserved : new String[]{"gateway", "api", "admin-api", "service"}) {
            adminOf(BRANDX_ISS).put().uri("/bff/admin/oidc-providers/google/roles")
                    .contentType(MediaType.APPLICATION_JSON)
                    .bodyValue("{\"roles\":[\"" + reserved + "\"]}")
                    .exchange().expectStatus().isBadRequest();
        }
        verify(repo, never()).replaceRoles(anyString(), anyString(), any());
    }

    @Test
    void setRoles_plainAdminAndCapabilityRoles_areAllowed() {
        // LEGIT CASE still works: plain 'admin' (in grantRole's allowlist) plus ordinary
        // capability roles are accepted and DO reach the repo — the denylist blocks only the
        // reserved escalation set, not the open capability set.
        when(repo.replaceRoles(eq("brandx"), eq("google"), any())).thenReturn(Mono.empty());
        adminOf(BRANDX_ISS).put().uri("/bff/admin/oidc-providers/google/roles")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"roles\":[\"user\",\"admin\",\"games_admin\"]}")
                .exchange().expectStatus().isOk();
        verify(repo).replaceRoles(eq("brandx"), eq("google"), any());
    }
}
