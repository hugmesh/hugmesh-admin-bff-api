package net.hugmesh.adminbff.capability;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webflux.test.autoconfigure.WebFluxTest;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.reactive.server.WebTestClient;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import net.hugmesh.adminbff.config.SecurityConfig;
import net.hugmesh.adminbff.web.ApiExceptionHandler;
import net.hugmesh.adminbff.web.ValidationExceptionHandler;
import net.hugmesh.commons.security.DomainRegistry;

import java.time.Instant;
import java.util.List;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.mockJwt;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.springSecurity;

/**
 * HTTP authorization matrix for {@link DomainCapabilityAdminController}
 * ({@code /bff/admin/domain-capabilities/**}). Driven through the REAL {@link SecurityConfig}
 * (the production {@code /bff/admin/** -> hasAnyRole('ADMIN','SUPERADMIN')} path gate + the
 * role hierarchy + the per-method {@code @PreAuthorize}), exactly like
 * {@code RadioDeviceControllerTest} / {@code FeatureNotificationControllerTest}. Proves:
 * <ul>
 *   <li>{@code list}: ADMIN + SUPERADMIN both reach it (SERVICE-scoped, not tested here —
 *       see {@link DomainCapabilityServiceTest#listForScope_scopedAdmin_listsOwnDomainOnly});
 *       MOD/USER/unauthenticated are denied.</li>
 *   <li>{@code setGranted} (the SUPERADMIN {@code granted} key): SUPERADMIN reaches it, an
 *       ADMIN is 403 and NEVER reaches the service (the {@code granted} key can never be
 *       touched by a non-superadmin) — including on the {@code ' global'} sentinel domain.</li>
 *   <li>{@code setEnabled} (the domain ADMIN {@code enabled} key): an ADMIN reaches it for
 *       their OWN domain, is 403 for ANOTHER domain and for {@code ' global'} (never
 *       reaching the service on either), and a SUPERADMIN reaches it for any domain
 *       including {@code ' global'}.</li>
 * </ul>
 */
@WebFluxTest(controllers = DomainCapabilityAdminController.class)
@Import({SecurityConfig.class, DomainRegistry.class, ValidationExceptionHandler.class,
        ApiExceptionHandler.class})
class DomainCapabilityAdminControllerTest {

    @Autowired ApplicationContext context;

    WebTestClient web;

    @BeforeEach
    void setUpWebTestClient() {
        web = WebTestClient.bindToApplicationContext(context).apply(springSecurity()).build();
    }

    @MockitoBean DomainCapabilityService service;
    @MockitoBean ReactiveJwtDecoder jwtDecoder;

    private static final String CAP = DomainCapability.USER_MESH_DEVICES;

    private static DomainCapability sample(String domain, boolean granted, boolean enabled) {
        return new DomainCapability("id", domain, CAP, granted, enabled, "root", Instant.now(), 1);
    }

    /**
     * The configured single-issuer (application.yml's {@code issuer-uri} default) —
     * {@link DomainRegistry} maps it to {@link DomainRegistry#DEFAULT_DOMAIN} ("default"),
     * exactly the {@code FeatureNotificationControllerTest} idiom. A JWT MUST carry it
     * (via {@code .issuer(ISSUER)}) or {@link net.hugmesh.commons.security.PrincipalDomain}
     * fails closed to {@code NO_DOMAIN} — so "default" is every principal's own resolved
     * domain below, and any OTHER literal domain string is "another domain".
     *
     * <p>The {@code roles} JWT CLAIM (not just the Spring-authority list {@code mockJwt()}
     * sets) must also be present: {@link net.hugmesh.commons.security.PrincipalDomain#resolve}
     * derives {@code superadmin()} via {@code Roles.isSuperadmin(Jwt)}, which reads the raw
     * claim — the converted Spring authority alone does not drive it.
     */
    private static final String ISSUER = "https://id.hugmesh.systems";

    private WebTestClient asSuperadmin() {
        return web.mutateWith(mockJwt().jwt(j -> j.issuer(ISSUER).claim("roles", List.of("superadmin")))
                .authorities(new SimpleGrantedAuthority("ROLE_USER"), new SimpleGrantedAuthority("ROLE_SUPERADMIN")));
    }

    private WebTestClient asAdmin() {
        return web.mutateWith(mockJwt().jwt(j -> j.issuer(ISSUER).claim("roles", List.of("admin")))
                .authorities(new SimpleGrantedAuthority("ROLE_USER"), new SimpleGrantedAuthority("ROLE_ADMIN")));
    }

    private WebTestClient asMod() {
        return web.mutateWith(mockJwt().jwt(j -> j.issuer(ISSUER))
                .authorities(new SimpleGrantedAuthority("ROLE_USER"), new SimpleGrantedAuthority("ROLE_MOD")));
    }

    private WebTestClient asUser() {
        return web.mutateWith(mockJwt().jwt(j -> j.issuer(ISSUER))
                .authorities(new SimpleGrantedAuthority("ROLE_USER")));
    }

    // ════════════════════════ list ═════════════════════════════════════════════════

    @Test
    void list_asSuperadmin_isAllowed() {
        when(service.listForScope(any())).thenReturn(Flux.just(sample("brandx", true, true)));
        asSuperadmin().get().uri("/bff/admin/domain-capabilities")
                .exchange().expectStatus().isOk();
        verify(service).listForScope(any());
    }

    @Test
    void list_asAdmin_isAllowed() {
        when(service.listForScope(any())).thenReturn(Flux.empty());
        asAdmin().get().uri("/bff/admin/domain-capabilities")
                .exchange().expectStatus().isOk();
        verify(service).listForScope(any());
    }

    @Test
    void list_asMod_isForbidden() {
        asMod().get().uri("/bff/admin/domain-capabilities").exchange().expectStatus().isForbidden();
        verify(service, never()).listForScope(any());
    }

    @Test
    void list_asUser_isForbidden() {
        asUser().get().uri("/bff/admin/domain-capabilities").exchange().expectStatus().isForbidden();
        verify(service, never()).listForScope(any());
    }

    @Test
    void list_unauthenticated_is401() {
        web.get().uri("/bff/admin/domain-capabilities").exchange().expectStatus().isUnauthorized();
        verify(service, never()).listForScope(any());
    }

    // ════════════════════════ setGranted — SUPERADMIN ONLY ═════════════════════════

    @Test
    void setGranted_asSuperadmin_isAllowed() {
        when(service.grant(eq("brandx"), eq(CAP), eq(true), anyString()))
                .thenReturn(Mono.just(sample("brandx", true, false)));
        asSuperadmin().put().uri("/bff/admin/domain-capabilities/brandx/" + CAP)
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"granted\":true}")
                .exchange().expectStatus().isOk()
                .expectBody().jsonPath("$.granted").isEqualTo(true);
        verify(service).grant(eq("brandx"), eq(CAP), eq(true), anyString());
    }

    @Test
    void setGranted_onGlobalSentinel_asSuperadmin_isAllowed_thePlatformWideKill() {
        when(service.grant(eq(DomainCapability.GLOBAL_DOMAIN), eq(CAP), eq(true), anyString()))
                .thenReturn(Mono.just(sample(DomainCapability.GLOBAL_DOMAIN, true, false)));
        asSuperadmin().put()
                .uri("/bff/admin/domain-capabilities/{domain}/{capability}",
                        DomainCapability.GLOBAL_DOMAIN, CAP)
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"granted\":true}")
                .exchange().expectStatus().isOk();
        verify(service).grant(eq(DomainCapability.GLOBAL_DOMAIN), eq(CAP), eq(true), anyString());
    }

    @Test
    void setGranted_asAdmin_isForbidden_andNeverWrites() {
        asAdmin().put().uri("/bff/admin/domain-capabilities/brandx/" + CAP)
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"granted\":true}")
                .exchange().expectStatus().isForbidden();
        verify(service, never()).grant(anyString(), anyString(), anyBoolean(), anyString());
    }

    @Test
    void setGranted_asAdmin_onOwnDomain_stillForbidden_cannotTouchGranted() {
        // Even on their OWN domain ("default" — see ISSUER's doc), an admin can never touch
        // the granted key.
        asAdmin().put().uri("/bff/admin/domain-capabilities/default/" + CAP)
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"granted\":true}")
                .exchange().expectStatus().isForbidden();
        verify(service, never()).grant(anyString(), anyString(), anyBoolean(), anyString());
    }

    @Test
    void setGranted_asMod_isForbidden() {
        asMod().put().uri("/bff/admin/domain-capabilities/brandx/" + CAP)
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"granted\":true}")
                .exchange().expectStatus().isForbidden();
        verify(service, never()).grant(anyString(), anyString(), anyBoolean(), anyString());
    }

    // ════════════════════════ setEnabled — ADMIN own-domain | SUPERADMIN any ═══════

    @Test
    void setEnabled_asAdmin_ownDomain_isAllowed() {
        // "default" is the admin's own resolved domain in this slice (see ISSUER's doc).
        when(service.enable(eq("default"), eq(CAP), eq(true), anyString()))
                .thenReturn(Mono.just(sample("default", true, true)));
        asAdmin().put().uri("/bff/admin/domain-capabilities/default/" + CAP + "/enabled")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"enabled\":true}")
                .exchange().expectStatus().isOk()
                .expectBody().jsonPath("$.enabled").isEqualTo(true);
        verify(service).enable(eq("default"), eq(CAP), eq(true), anyString());
    }

    @Test
    void setEnabled_asAdmin_anotherDomain_isForbidden_andNeverWrites() {
        // "brandy" is NOT the admin's own resolved domain ("default" — see ISSUER's doc).
        asAdmin().put().uri("/bff/admin/domain-capabilities/brandy/" + CAP + "/enabled")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"enabled\":true}")
                .exchange().expectStatus().isForbidden();
        verify(service, never()).enable(anyString(), anyString(), anyBoolean(), anyString());
    }

    @Test
    void setEnabled_asAdmin_onGlobalSentinel_isForbidden_andNeverWrites() {
        asAdmin().put()
                .uri("/bff/admin/domain-capabilities/{domain}/{capability}/enabled",
                        DomainCapability.GLOBAL_DOMAIN, CAP)
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"enabled\":true}")
                .exchange().expectStatus().isForbidden();
        verify(service, never()).enable(anyString(), anyString(), anyBoolean(), anyString());
    }

    @Test
    void setEnabled_asSuperadmin_anyDomain_isAllowed() {
        when(service.enable(eq("brandy"), eq(CAP), eq(true), anyString()))
                .thenReturn(Mono.just(sample("brandy", true, true)));
        asSuperadmin().put().uri("/bff/admin/domain-capabilities/brandy/" + CAP + "/enabled")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"enabled\":true}")
                .exchange().expectStatus().isOk();
        verify(service).enable(eq("brandy"), eq(CAP), eq(true), anyString());
    }

    @Test
    void setEnabled_asSuperadmin_onGlobalSentinel_isAllowed() {
        when(service.enable(eq(DomainCapability.GLOBAL_DOMAIN), eq(CAP), eq(true), anyString()))
                .thenReturn(Mono.just(sample(DomainCapability.GLOBAL_DOMAIN, false, true)));
        asSuperadmin().put()
                .uri("/bff/admin/domain-capabilities/{domain}/{capability}/enabled",
                        DomainCapability.GLOBAL_DOMAIN, CAP)
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"enabled\":true}")
                .exchange().expectStatus().isOk();
        verify(service).enable(eq(DomainCapability.GLOBAL_DOMAIN), eq(CAP), eq(true), anyString());
    }

    @Test
    void setEnabled_asMod_isForbidden() {
        asMod().put().uri("/bff/admin/domain-capabilities/brandx/" + CAP + "/enabled")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"enabled\":true}")
                .exchange().expectStatus().isForbidden();
        verify(service, never()).enable(anyString(), anyString(), anyBoolean(), anyString());
    }

    @Test
    void setEnabled_unauthenticated_is401() {
        web.put().uri("/bff/admin/domain-capabilities/brandx/" + CAP + "/enabled")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"enabled\":true}")
                .exchange().expectStatus().isUnauthorized();
        verify(service, never()).enable(anyString(), anyString(), anyBoolean(), anyString());
    }
}
