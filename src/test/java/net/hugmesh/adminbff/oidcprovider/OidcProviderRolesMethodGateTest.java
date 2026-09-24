package net.hugmesh.adminbff.oidcprovider;

import net.hugmesh.commons.security.DomainRegistry;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.webflux.test.autoconfigure.WebFluxTest;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.http.MediaType;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.security.access.expression.method.DefaultMethodSecurityExpressionHandler;
import org.springframework.security.access.expression.method.MethodSecurityExpressionHandler;
import org.springframework.security.config.annotation.method.configuration.EnableReactiveMethodSecurity;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.reactive.server.WebTestClient;
import reactor.core.publisher.Flux;
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
 * Pins the PER-METHOD authorization layer of {@link OidcProviderRolesController} ON ITS OWN.
 *
 * <p>Why this class exists, measured (#60): {@code OidcProviderRolesControllerAuthzTest} runs
 * the real {@code SecurityConfig}, whose path rule {@code /bff/admin/** ->
 * hasAnyRole('ADMIN','SUPERADMIN')} (SecurityConfig.java:284) independently denies MOD and
 * USER. Deleting all three {@code @PreAuthorize("hasRole('ADMIN')")} annotations from the
 * controller (on {@code listProviderRoles}, {@code setProviderRoles} and
 * {@code clearProviderRoles}) left that suite fully green (19/19) — it can only detect the
 * loss of both layers at once, never of either one. This class removes the path layer (the
 * chain below is {@code permitAll}) so the ONLY thing that can deny MOD/USER is the
 * {@code @PreAuthorize} on the handler method. Drop any one of the three annotations and the
 * matching test below fails.
 *
 * <p>Deliberately NOT a duplicate of the full-stack matrix: domain scoping, cross-tenant
 * isolation, input validation and the reserved-role denylist stay in
 * {@code OidcProviderRolesControllerAuthzTest}, which exercises the production chain.
 * Pattern follows {@code RoleMfaPolicyMethodGateTest}.
 */
@WebFluxTest(controllers = OidcProviderRolesController.class)
class OidcProviderRolesMethodGateTest {

    static final String BRANDX_ISS = "https://idp.brandx.example";
    static final String BASE = "/bff/admin/oidc-providers";

    /**
     * Method security WITHOUT the production path gate: every exchange is permitted at the
     * path layer, so an authorization failure can only come from {@code @PreAuthorize}. The
     * role hierarchy mirrors SecurityConfig.java:608 so SUPERADMIN still satisfies
     * {@code hasRole('ADMIN')} through method security alone.
     */
    @TestConfiguration
    @EnableWebFluxSecurity
    @EnableReactiveMethodSecurity
    static class MethodSecurityOnly {

        @Bean
        SecurityWebFilterChain permitAllPaths(ServerHttpSecurity http) {
            return http
                    .csrf(ServerHttpSecurity.CsrfSpec::disable)
                    .authorizeExchange(ex -> ex.anyExchange().permitAll())
                    .build();
        }

        @Bean
        RoleHierarchy roleHierarchy() {
            return RoleHierarchyImpl.fromHierarchy(
                    "ROLE_SUPERADMIN > ROLE_ADMIN\n"
                            + "ROLE_SUPERADMIN > ROLE_MOD\n"
                            + "ROLE_SUPERADMIN > ROLE_USER");
        }

        // NOT named "methodSecurityExpressionHandler" — collides with Spring Security's own
        // fallback bean definition and fails context startup with a
        // BeanDefinitionOverrideException. See RoleMfaPolicyMethodGateTest for the same trap.
        @Bean
        MethodSecurityExpressionHandler gateMethodSecurityExpressionHandler(RoleHierarchy roleHierarchy) {
            var handler = new DefaultMethodSecurityExpressionHandler();
            handler.setRoleHierarchy(roleHierarchy);
            return handler;
        }

        @Bean
        DomainRegistry domainRegistry() {
            return new DomainRegistry("", BRANDX_ISS + "=brandx");
        }
    }

    @Autowired ApplicationContext context;

    WebTestClient web;

    @MockitoBean OidcProviderRoleRepository repo;
    @MockitoBean ReactiveJwtDecoder jwtDecoder;

    @BeforeEach
    void setUpWebTestClient() {
        web = WebTestClient.bindToApplicationContext(context).apply(springSecurity()).build();
    }

    private WebTestClient as(String... roles) {
        SimpleGrantedAuthority[] auths = new SimpleGrantedAuthority[roles.length];
        for (int i = 0; i < roles.length; i++) auths[i] = new SimpleGrantedAuthority(roles[i]);
        return web.mutateWith(mockJwt()
                .jwt(j -> j.issuer(BRANDX_ISS).subject("subj"))
                .authorities(auths));
    }

    // ═══ the gate ALLOWS what it must, with no path rule helping ═══════════════════════

    @Test
    void list_asAdmin_reachesTheRepo_withNoPathRule() {
        when(repo.listByDomain(anyString())).thenReturn(Flux.empty());
        as("ROLE_USER", "ROLE_ADMIN").get().uri(BASE + "/roles").exchange().expectStatus().isOk();
        verify(repo).listByDomain(eq("brandx"));
    }

    @Test
    void list_asSuperadmin_reachesTheRepo_throughTheRoleHierarchyAlone() {
        when(repo.listByDomain(anyString())).thenReturn(Flux.empty());
        as("ROLE_USER", "ROLE_SUPERADMIN").get().uri(BASE + "/roles").exchange().expectStatus().isOk();
        verify(repo).listByDomain(eq("brandx"));
    }

    // ═══ the gate DENIES on its own — these fail if @PreAuthorize is dropped ══════════

    @Test
    void list_asMod_isForbiddenByThePerMethodGateAlone_andNeverReads() {
        // stubbed on purpose: if the gate is dropped the call SUCCEEDS (200) and the
        // never() below is what reports it — not an incidental NPE.
        when(repo.listByDomain(anyString())).thenReturn(Flux.empty());
        as("ROLE_USER", "ROLE_MOD").get().uri(BASE + "/roles").exchange().expectStatus().isForbidden();
        verify(repo, never()).listByDomain(anyString());
    }

    @Test
    void list_asUser_isForbiddenByThePerMethodGateAlone_andNeverReads() {
        when(repo.listByDomain(anyString())).thenReturn(Flux.empty());
        as("ROLE_USER").get().uri(BASE + "/roles").exchange().expectStatus().isForbidden();
        verify(repo, never()).listByDomain(anyString());
    }

    @Test
    void set_asAdmin_reachesTheRepo_withNoPathRule() {
        when(repo.replaceRoles(eq("brandx"), eq("google"), any())).thenReturn(Mono.empty());
        as("ROLE_USER", "ROLE_ADMIN").put().uri(BASE + "/google/roles")
                .contentType(MediaType.APPLICATION_JSON).bodyValue("{\"roles\":[\"user\"]}")
                .exchange().expectStatus().isOk();
        verify(repo).replaceRoles(eq("brandx"), eq("google"), any());
    }

    @Test
    void set_asMod_isForbiddenByThePerMethodGateAlone_andNeverWrites() {
        when(repo.replaceRoles(anyString(), anyString(), any())).thenReturn(Mono.empty());
        as("ROLE_USER", "ROLE_MOD").put().uri(BASE + "/google/roles")
                .contentType(MediaType.APPLICATION_JSON).bodyValue("{\"roles\":[\"user\"]}")
                .exchange().expectStatus().isForbidden();
        verify(repo, never()).replaceRoles(anyString(), anyString(), any());
    }

    @Test
    void set_asUser_isForbiddenByThePerMethodGateAlone_andNeverWrites() {
        when(repo.replaceRoles(anyString(), anyString(), any())).thenReturn(Mono.empty());
        as("ROLE_USER").put().uri(BASE + "/google/roles")
                .contentType(MediaType.APPLICATION_JSON).bodyValue("{\"roles\":[\"user\"]}")
                .exchange().expectStatus().isForbidden();
        verify(repo, never()).replaceRoles(anyString(), anyString(), any());
    }

    @Test
    void clear_asAdmin_reachesTheRepo_withNoPathRule() {
        when(repo.clearRoles(eq("brandx"), eq("google"))).thenReturn(Mono.empty());
        as("ROLE_USER", "ROLE_ADMIN").delete().uri(BASE + "/google/roles")
                .exchange().expectStatus().isOk();
        verify(repo).clearRoles(eq("brandx"), eq("google"));
    }

    @Test
    void clear_asMod_isForbiddenByThePerMethodGateAlone_andNeverClears() {
        when(repo.clearRoles(anyString(), anyString())).thenReturn(Mono.empty());
        as("ROLE_USER", "ROLE_MOD").delete().uri(BASE + "/google/roles")
                .exchange().expectStatus().isForbidden();
        verify(repo, never()).clearRoles(anyString(), anyString());
    }

    @Test
    void clear_asUser_isForbiddenByThePerMethodGateAlone_andNeverClears() {
        when(repo.clearRoles(anyString(), anyString())).thenReturn(Mono.empty());
        as("ROLE_USER").delete().uri(BASE + "/google/roles")
                .exchange().expectStatus().isForbidden();
        verify(repo, never()).clearRoles(anyString(), anyString());
    }
}
