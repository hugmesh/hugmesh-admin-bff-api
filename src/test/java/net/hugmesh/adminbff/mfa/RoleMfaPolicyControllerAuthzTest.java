package net.hugmesh.adminbff.mfa;

import net.hugmesh.adminbff.config.SecurityConfig;
import net.hugmesh.adminbff.web.ApiExceptionHandler;
import net.hugmesh.adminbff.web.ValidationExceptionHandler;
import net.hugmesh.commons.security.DomainRegistry;
import net.hugmesh.commons.web.ApiException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.webflux.test.autoconfigure.WebFluxTest;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
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
 * HTTP authorization + domain-scoping matrix for {@link RoleMfaPolicyController}
 * ({@code /bff/admin/mfa/role-policy/**}), driven through the REAL {@link SecurityConfig}
 * (the production {@code /bff/admin/** -> hasAnyRole('ADMIN','SUPERADMIN')} path gate + the
 * role hierarchy + the per-method {@code @PreAuthorize("hasRole('ADMIN')")}) — the same
 * shape as {@code OidcProviderRolesControllerAuthzTest}.
 *
 * <ol>
 *   <li><b>ROLE GATE</b> — ADMIN ALLOW; SUPERADMIN ALLOW; MOD/USER 403; anonymous 401. Every
 *       DENY verifies the service was NEVER called (mutation-resistant: drop the
 *       {@code @PreAuthorize} or the path rule and MOD/USER reach the service).</li>
 *   <li><b>DOMAIN FROM THE VALIDATED ISSUER</b> — the {@code domain} the service is asked for
 *       is derived from the token's {@code iss} via {@link DomainRegistry}, never from the
 *       request. Asserted by capturing the EXACT domain argument per brand.</li>
 *   <li><b>FAIL CLOSED ON NO DOMAIN</b> — a principal whose issuer the registry does not know
 *       gets 403 and the service is never called (this controller is deliberately stricter
 *       than the OIDC-provider one here).</li>
 *   <li><b>VALIDATION</b> — a malformed role path segment is 400 before the service runs; a
 *       service-side refusal (the floor) surfaces as the {@link ApiException} 400.</li>
 * </ol>
 */
@WebFluxTest(controllers = RoleMfaPolicyController.class)
@Import({SecurityConfig.class, ValidationExceptionHandler.class, ApiExceptionHandler.class})
class RoleMfaPolicyControllerAuthzTest {

    static final String BRANDX_ISS = "https://idp.brandx.example";
    static final String BRANDY_ISS = "https://idp.brandy.example";
    static final String UNKNOWN_ISS = "https://idp.nobody.example";

    static final String BASE = "/bff/admin/mfa/role-policy";

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

    @MockitoBean RoleMfaPolicyService service;
    @MockitoBean ReactiveJwtDecoder jwtDecoder;

    private static RoleMfaPolicy policy(String domain, String role, boolean required) {
        return new RoleMfaPolicy(domain, role, required, List.of(), 0L, false,
                RoleMfaPolicyService.FLOOR_ROLES.contains(role), null, null);
    }

    private WebTestClient as(String issuer, String... roles) {
        SimpleGrantedAuthority[] auths = new SimpleGrantedAuthority[roles.length];
        for (int i = 0; i < roles.length; i++) auths[i] = new SimpleGrantedAuthority(roles[i]);
        return web.mutateWith(mockJwt()
                .jwt(j -> j.issuer(issuer).subject("subj").claim("roles", roleNamesOf(roles)))
                .authorities(auths));
    }

    private static List<String> roleNamesOf(String[] roles) {
        return java.util.Arrays.stream(roles)
                .map(r -> r.startsWith("ROLE_") ? r.substring("ROLE_".length()).toLowerCase() : r.toLowerCase())
                .toList();
    }

    private WebTestClient adminOf(String issuer)      { return as(issuer, "ROLE_USER", "ROLE_ADMIN"); }
    private WebTestClient superadminOf(String issuer) { return as(issuer, "ROLE_USER", "ROLE_SUPERADMIN"); }
    private WebTestClient modOf(String issuer)        { return as(issuer, "ROLE_USER", "ROLE_MOD"); }
    private WebTestClient userOf(String issuer)       { return as(issuer, "ROLE_USER"); }

    private static final String SET_MOD_REQUIRED = "{\"required\":true,\"methods\":[\"webauthn\"],\"graceSeconds\":60}";

    // ════════════════════════ ROLE GATE — list (GET) ══════════════════════════════════

    @Test
    void list_asAdmin_authorized_scopedToOwnDomain() {
        when(service.listEffective(eq("brandx"))).thenReturn(Flux.just(
                policy("brandx", "superadmin", true), policy("brandx", "admin", true),
                policy("brandx", "mod", false), policy("brandx", "user", false)));
        adminOf(BRANDX_ISS).get().uri(BASE)
                .exchange().expectStatus().isOk()
                .expectBody()
                .jsonPath("$.domain").isEqualTo("brandx")
                .jsonPath("$.policies.length()").isEqualTo(4)
                .jsonPath("$.policies[1].role").isEqualTo("admin")
                .jsonPath("$.policies[1].required").isEqualTo(true)
                .jsonPath("$.policies[1].floor").isEqualTo(true)
                .jsonPath("$.policies[2].role").isEqualTo("mod")
                .jsonPath("$.policies[2].required").isEqualTo(false);
        verify(service).listEffective(eq("brandx"));
    }

    @Test
    void list_asBrandYAdmin_isScopedToBrandY_notBrandX() {
        when(service.listEffective(anyString())).thenReturn(Flux.empty());
        adminOf(BRANDY_ISS).get().uri(BASE).exchange().expectStatus().isOk();
        verify(service).listEffective(eq("brandy"));
        verify(service, never()).listEffective(eq("brandx"));
    }

    @Test
    void list_asSuperadmin_authorized() {
        when(service.listEffective(anyString())).thenReturn(Flux.empty());
        superadminOf(BRANDX_ISS).get().uri(BASE).exchange().expectStatus().isOk();
        verify(service).listEffective(anyString());
    }

    @Test
    void list_asMod_isForbidden_andNeverReads() {
        modOf(BRANDX_ISS).get().uri(BASE).exchange().expectStatus().isForbidden();
        verify(service, never()).listEffective(anyString());
    }

    @Test
    void list_asUser_isForbidden_andNeverReads() {
        userOf(BRANDX_ISS).get().uri(BASE).exchange().expectStatus().isForbidden();
        verify(service, never()).listEffective(anyString());
    }

    @Test
    void list_anonymous_isUnauthorized() {
        web.get().uri(BASE).exchange().expectStatus().isUnauthorized();
        verify(service, never()).listEffective(anyString());
    }

    @Test
    void list_adminWithUnresolvableIssuer_isForbidden_failClosed_andNeverReads() {
        adminOf(UNKNOWN_ISS).get().uri(BASE).exchange().expectStatus().isForbidden();
        verify(service, never()).listEffective(anyString());
    }

    // ════════════════════════ ROLE GATE — set (PUT) ═══════════════════════════════════

    @Test
    void set_asAdmin_authorized_scopedToOwnDomain_withCallerAsUpdatedBy() {
        when(service.upsert(eq("brandx"), eq("mod"), eq(true), eq(List.of("webauthn")), eq(60L), eq("subj")))
                .thenReturn(Mono.just(policy("brandx", "mod", true)));
        adminOf(BRANDX_ISS).put().uri(BASE + "/mod")
                .contentType(MediaType.APPLICATION_JSON).bodyValue(SET_MOD_REQUIRED)
                .exchange().expectStatus().isOk()
                .expectBody()
                .jsonPath("$.domain").isEqualTo("brandx")
                .jsonPath("$.role").isEqualTo("mod")
                .jsonPath("$.required").isEqualTo(true);
        // domain from the VALIDATED issuer; updatedBy is the token subject.
        verify(service).upsert(eq("brandx"), eq("mod"), eq(true), eq(List.of("webauthn")), eq(60L), eq("subj"));
    }

    @Test
    void set_asBrandYAdmin_writesBrandY_notBrandX() {
        when(service.upsert(anyString(), anyString(), anyBoolean(), any(), anyLong(), anyString()))
                .thenReturn(Mono.just(policy("brandy", "mod", true)));
        adminOf(BRANDY_ISS).put().uri(BASE + "/mod")
                .contentType(MediaType.APPLICATION_JSON).bodyValue(SET_MOD_REQUIRED)
                .exchange().expectStatus().isOk();
        verify(service).upsert(eq("brandy"), eq("mod"), anyBoolean(), any(), anyLong(), anyString());
        verify(service, never()).upsert(eq("brandx"), anyString(), anyBoolean(), any(), anyLong(), anyString());
    }

    @Test
    void set_asSuperadmin_authorized() {
        when(service.upsert(anyString(), anyString(), anyBoolean(), any(), anyLong(), anyString()))
                .thenReturn(Mono.just(policy("brandx", "mod", true)));
        superadminOf(BRANDX_ISS).put().uri(BASE + "/mod")
                .contentType(MediaType.APPLICATION_JSON).bodyValue(SET_MOD_REQUIRED)
                .exchange().expectStatus().isOk();
        verify(service).upsert(anyString(), eq("mod"), anyBoolean(), any(), anyLong(), anyString());
    }

    @Test
    void set_asMod_isForbidden_andNeverWrites() {
        modOf(BRANDX_ISS).put().uri(BASE + "/mod")
                .contentType(MediaType.APPLICATION_JSON).bodyValue(SET_MOD_REQUIRED)
                .exchange().expectStatus().isForbidden();
        verify(service, never()).upsert(anyString(), anyString(), anyBoolean(), any(), anyLong(), anyString());
    }

    @Test
    void set_asUser_isForbidden_andNeverWrites() {
        userOf(BRANDX_ISS).put().uri(BASE + "/mod")
                .contentType(MediaType.APPLICATION_JSON).bodyValue(SET_MOD_REQUIRED)
                .exchange().expectStatus().isForbidden();
        verify(service, never()).upsert(anyString(), anyString(), anyBoolean(), any(), anyLong(), anyString());
    }

    @Test
    void set_anonymous_isUnauthorized() {
        web.put().uri(BASE + "/mod")
                .contentType(MediaType.APPLICATION_JSON).bodyValue(SET_MOD_REQUIRED)
                .exchange().expectStatus().isUnauthorized();
        verify(service, never()).upsert(anyString(), anyString(), anyBoolean(), any(), anyLong(), anyString());
    }

    @Test
    void set_adminWithUnresolvableIssuer_isForbidden_failClosed_andNeverWrites() {
        adminOf(UNKNOWN_ISS).put().uri(BASE + "/mod")
                .contentType(MediaType.APPLICATION_JSON).bodyValue(SET_MOD_REQUIRED)
                .exchange().expectStatus().isForbidden();
        verify(service, never()).upsert(anyString(), anyString(), anyBoolean(), any(), anyLong(), anyString());
    }

    // ════════════════════════ VALIDATION ═════════════════════════════════════════════

    @Test
    void set_malformedRolePathSegment_isBadRequest_beforeTheService() {
        adminOf(BRANDX_ISS).put().uri(BASE + "/mod%20role")
                .contentType(MediaType.APPLICATION_JSON).bodyValue(SET_MOD_REQUIRED)
                .exchange().expectStatus().isBadRequest();
        verify(service, never()).upsert(anyString(), anyString(), anyBoolean(), any(), anyLong(), anyString());
    }

    @Test
    void set_graceAboveTheBound_isBadRequest_beforeTheService() {
        adminOf(BRANDX_ISS).put().uri(BASE + "/mod")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"required\":true,\"methods\":[],\"graceSeconds\":" + (RoleMfaPolicyService.MAX_GRACE_SECONDS + 1) + "}")
                .exchange().expectStatus().isBadRequest();
        verify(service, never()).upsert(anyString(), anyString(), anyBoolean(), any(), anyLong(), anyString());
    }

    @Test
    void set_serviceFloorRefusal_surfacesAs400() {
        when(service.upsert(eq("brandx"), eq("admin"), eq(false), any(), anyLong(), anyString()))
                .thenReturn(Mono.error(ApiException.badRequest("role 'admin' is on the privileged MFA floor")));
        adminOf(BRANDX_ISS).put().uri(BASE + "/admin")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"required\":false,\"methods\":[],\"graceSeconds\":0}")
                .exchange().expectStatus().isBadRequest();
    }
}
