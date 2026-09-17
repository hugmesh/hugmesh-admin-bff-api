package net.hugmesh.adminbff.mfa;

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

import java.util.List;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.mockJwt;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.springSecurity;

/**
 * Pins the PER-METHOD authorization layer of {@link RoleMfaPolicyController} ON ITS OWN.
 *
 * <p>Why this class exists, measured: {@code RoleMfaPolicyControllerAuthzTest} runs the real
 * {@link net.hugmesh.adminbff.config.SecurityConfig}, whose path rule
 * {@code /bff/admin/** -> hasAnyRole('ADMIN','SUPERADMIN')} (SecurityConfig.java:284)
 * independently denies MOD and USER. Deleting BOTH {@code @PreAuthorize("hasRole('ADMIN')")}
 * annotations from the controller leaves that suite fully GREEN — so it can only detect the
 * loss of both layers at once, never of either one. This class removes the path layer (the
 * chain below is {@code permitAll}) so the ONLY thing that can deny MOD/USER is the
 * {@code @PreAuthorize} on the handler method. Drop either annotation and a test here fails.
 *
 * <p>Deliberately NOT a duplicate of the full-stack matrix: domain scoping, the NO_DOMAIN
 * fail-closed 403, validation and anonymous handling stay in
 * {@code RoleMfaPolicyControllerAuthzTest}, which exercises the production chain.
 */
@WebFluxTest(controllers = RoleMfaPolicyController.class)
class RoleMfaPolicyMethodGateTest {

    static final String BRANDX_ISS = "https://idp.brandx.example";
    static final String BASE = "/bff/admin/mfa/role-policy";

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

    @MockitoBean RoleMfaPolicyService service;
    @MockitoBean ReactiveJwtDecoder jwtDecoder;

    @BeforeEach
    void setUpWebTestClient() {
        web = WebTestClient.bindToApplicationContext(context).apply(springSecurity()).build();
    }

    private static final String SET_MOD_REQUIRED =
            "{\"required\":true,\"methods\":[\"webauthn\"],\"graceSeconds\":60}";

    private WebTestClient as(String... roles) {
        SimpleGrantedAuthority[] auths = new SimpleGrantedAuthority[roles.length];
        for (int i = 0; i < roles.length; i++) auths[i] = new SimpleGrantedAuthority(roles[i]);
        return web.mutateWith(mockJwt()
                .jwt(j -> j.issuer(BRANDX_ISS).subject("subj"))
                .authorities(auths));
    }

    private static RoleMfaPolicy policy(String role, boolean required) {
        return new RoleMfaPolicy("brandx", role, required, List.of(), 0L, false,
                RoleMfaPolicyService.FLOOR_ROLES.contains(role), null, null);
    }

    // ═══ the gate ALLOWS what it must, with no path rule helping ═══════════════════════

    @Test
    void list_asAdmin_reachesTheService_withNoPathRule() {
        when(service.listEffective(eq("brandx"))).thenReturn(Flux.just(policy("mod", false)));
        as("ROLE_USER", "ROLE_ADMIN").get().uri(BASE).exchange().expectStatus().isOk();
        verify(service).listEffective(eq("brandx"));
    }

    @Test
    void list_asSuperadmin_reachesTheService_throughTheRoleHierarchyAlone() {
        when(service.listEffective(anyString())).thenReturn(Flux.empty());
        as("ROLE_USER", "ROLE_SUPERADMIN").get().uri(BASE).exchange().expectStatus().isOk();
        verify(service).listEffective(eq("brandx"));
    }

    // ═══ the gate DENIES on its own — these fail if @PreAuthorize is dropped ══════════

    @Test
    void list_asMod_isForbiddenByThePerMethodGateAlone_andNeverReads() {
        // stubbed on purpose: if the gate is dropped the call SUCCEEDS (200) and the
        // never() below is what reports it — not an incidental NPE.
        when(service.listEffective(anyString())).thenReturn(Flux.empty());
        as("ROLE_USER", "ROLE_MOD").get().uri(BASE).exchange().expectStatus().isForbidden();
        verify(service, never()).listEffective(anyString());
    }

    @Test
    void list_asUser_isForbiddenByThePerMethodGateAlone_andNeverReads() {
        when(service.listEffective(anyString())).thenReturn(Flux.empty());
        as("ROLE_USER").get().uri(BASE).exchange().expectStatus().isForbidden();
        verify(service, never()).listEffective(anyString());
    }

    @Test
    void set_asAdmin_reachesTheService_withNoPathRule() {
        when(service.upsert(eq("brandx"), eq("mod"), eq(true), eq(List.of("webauthn")), eq(60L), eq("subj")))
                .thenReturn(Mono.just(policy("mod", true)));
        as("ROLE_USER", "ROLE_ADMIN").put().uri(BASE + "/mod")
                .contentType(MediaType.APPLICATION_JSON).bodyValue(SET_MOD_REQUIRED)
                .exchange().expectStatus().isOk();
        verify(service).upsert(eq("brandx"), eq("mod"), eq(true), eq(List.of("webauthn")), eq(60L), eq("subj"));
    }

    @Test
    void set_asMod_isForbiddenByThePerMethodGateAlone_andNeverWrites() {
        when(service.upsert(anyString(), anyString(), anyBoolean(), any(), anyLong(), anyString()))
                .thenReturn(Mono.just(policy("mod", true)));
        as("ROLE_USER", "ROLE_MOD").put().uri(BASE + "/mod")
                .contentType(MediaType.APPLICATION_JSON).bodyValue(SET_MOD_REQUIRED)
                .exchange().expectStatus().isForbidden();
        verify(service, never()).upsert(anyString(), anyString(), anyBoolean(), any(), anyLong(), anyString());
    }

    @Test
    void set_asUser_isForbiddenByThePerMethodGateAlone_andNeverWrites() {
        when(service.upsert(anyString(), anyString(), anyBoolean(), any(), anyLong(), anyString()))
                .thenReturn(Mono.just(policy("mod", true)));
        as("ROLE_USER").put().uri(BASE + "/mod")
                .contentType(MediaType.APPLICATION_JSON).bodyValue(SET_MOD_REQUIRED)
                .exchange().expectStatus().isForbidden();
        verify(service, never()).upsert(anyString(), anyString(), anyBoolean(), any(), anyLong(), anyString());
    }
}
