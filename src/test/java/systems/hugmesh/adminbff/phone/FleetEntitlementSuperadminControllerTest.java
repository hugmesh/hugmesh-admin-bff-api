package systems.hugmesh.adminbff.phone;

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
import systems.hugmesh.adminbff.config.SecurityConfig;
import systems.hugmesh.adminbff.web.ApiExceptionHandler;
import systems.hugmesh.adminbff.web.ValidationExceptionHandler;
import systems.hugmesh.commons.security.DomainRegistry;

import java.time.Instant;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.mockJwt;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.springSecurity;

/**
 * The SUPERADMIN admin surface for the fleet-admin entitlement gate
 * ({@code /bff/superadmin/fleet-entitlements/**}, changeset 306) — the acceptance bar for the
 * SUPERADMIN-only, step-up-gated boundary that grants/revokes the subscription a non-superadmin
 * FLEET_ADMIN needs. {@code @WebFluxTest} + the real {@link SecurityConfig} so BOTH the coarse
 * {@code /bff/superadmin/**} gate AND the per-method {@code @PreAuthorize} run; the service + gates
 * are mocked so every REFUSAL is proven to happen BEFORE the service.
 *
 * <ul>
 *   <li>SUPERADMIN — list (no step-up), upsert + delete (with step-up) each reach the service;</li>
 *   <li>a bare {@code {}} upsert defaults {@code active=true} (mirrors the column default);</li>
 *   <li>ADMIN / USER — 403 on EVERY endpoint, service NEVER called; unauthenticated — 401;</li>
 *   <li>the two MUTATIONS with NO step-up (MFA dark) — 403, service NEVER called;</li>
 *   <li>a fresh Casdoor-MFA stamp satisfies step-up with no token and is consumed single-use.</li>
 * </ul>
 */
@WebFluxTest(controllers = FleetEntitlementSuperadminController.class)
@Import({SecurityConfig.class, DomainRegistry.class, ValidationExceptionHandler.class, ApiExceptionHandler.class})
class FleetEntitlementSuperadminControllerTest {

    private static final String STEP_UP = PhoneLockStepUpGate.STEP_UP_HEADER;
    private static final String TOKEN = "good-token";
    private static final String BASE = "/bff/superadmin/fleet-entitlements";

    @Autowired ApplicationContext context;

    WebTestClient web;

    @MockitoBean FleetEntitlementService service;
    @MockitoBean PhoneLockStepUpGate stepUp;
    @MockitoBean systems.hugmesh.authcore.casdoor.MfaStepUpService mfaStepUp;
    @MockitoBean ReactiveJwtDecoder jwtDecoder;

    @BeforeEach
    void setUp() {
        web = WebTestClient.bindToApplicationContext(context).apply(springSecurity()).build();
    }

    @BeforeEach
    void mfaDarkByDefault() {
        when(mfaStepUp.isFresh(any())).thenReturn(Mono.just(false));
        when(mfaStepUp.consume(any())).thenReturn(Mono.empty());
        when(stepUp.isSatisfied(anyString(), any(), anyBoolean()))
                .thenAnswer(inv -> inv.<Boolean>getArgument(2)
                        || stepUp.isSatisfied(inv.getArgument(0), inv.getArgument(1)));
    }

    private static FleetEntitlement ent(String subject, boolean active) {
        return new FleetEntitlement(subject, active, 5, Instant.parse("2027-01-01T00:00:00Z"),
                Instant.parse("2026-07-22T00:00:00Z"));
    }

    private WebTestClient asSuperadmin() {
        return web.mutateWith(mockJwt().authorities(
                new SimpleGrantedAuthority("ROLE_USER"), new SimpleGrantedAuthority("ROLE_SUPERADMIN")));
    }

    private WebTestClient asAdmin() {
        return web.mutateWith(mockJwt().authorities(
                new SimpleGrantedAuthority("ROLE_USER"), new SimpleGrantedAuthority("ROLE_ADMIN")));
    }

    private WebTestClient asUser() {
        return web.mutateWith(mockJwt().authorities(new SimpleGrantedAuthority("ROLE_USER")));
    }

    // ── list (SUPERADMIN read, no step-up) ───────────────────────────────────────────
    @Test
    void list_superadmin_seesEnvelope() {
        when(service.list()).thenReturn(Flux.just(ent("sub-a", true), ent("sub-b", false)));
        asSuperadmin().get().uri(BASE)
                .exchange().expectStatus().isOk()
                .expectBody()
                .jsonPath("$.entitlements.length()").isEqualTo(2)
                .jsonPath("$.entitlements[0].subject").isEqualTo("sub-a")
                .jsonPath("$.entitlements[0].active").isEqualTo(true)
                .jsonPath("$.entitlements[0].seats").isEqualTo(5);
    }

    @Test
    void list_admin_forbidden_neverReachesService() {
        asAdmin().get().uri(BASE).exchange().expectStatus().isForbidden();
        asUser().get().uri(BASE).exchange().expectStatus().isForbidden();
        verify(service, never()).list();
    }

    @Test
    void list_unauthenticated_401() {
        web.get().uri(BASE).exchange().expectStatus().isUnauthorized();
        verify(service, never()).list();
    }

    // ── upsert (SUPERADMIN + step-up) ────────────────────────────────────────────────
    @Test
    void upsert_superadmin_withStepUp_reachesService() {
        when(stepUp.isSatisfied(any(), eq(TOKEN))).thenReturn(true);
        when(service.upsert(eq("sub-1"), eq(true), eq(5), any()))
                .thenReturn(Mono.just(ent("sub-1", true)));
        asSuperadmin().put().uri(BASE + "/sub-1")
                .header(STEP_UP, TOKEN).contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"active\":true,\"seats\":5,\"expiresAt\":\"2027-01-01T00:00:00Z\"}")
                .exchange().expectStatus().isOk()
                .expectBody().jsonPath("$.subject").isEqualTo("sub-1")
                .jsonPath("$.active").isEqualTo(true);
    }

    @Test
    void upsert_bareBody_defaultsActiveTrue() {
        when(stepUp.isSatisfied(any(), eq(TOKEN))).thenReturn(true);
        when(service.upsert(eq("sub-1"), eq(true), isNull(), isNull()))
                .thenReturn(Mono.just(ent("sub-1", true)));
        asSuperadmin().put().uri(BASE + "/sub-1")
                .header(STEP_UP, TOKEN).contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{}")
                .exchange().expectStatus().isOk();
        // active defaults to true (mirrors the column default) when the body omits it.
        verify(service).upsert(eq("sub-1"), eq(true), isNull(), isNull());
    }

    @Test
    void upsert_admin_forbidden_neverReachesService() {
        asAdmin().put().uri(BASE + "/sub-1")
                .header(STEP_UP, TOKEN).contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"active\":true}")
                .exchange().expectStatus().isForbidden();
        verify(service, never()).upsert(any(), anyBoolean(), any(), any());
    }

    @Test
    void upsert_missingStepUp_mfaDark_403_neverReachesService() {
        when(stepUp.isSatisfied(any(), any())).thenReturn(false);
        asSuperadmin().put().uri(BASE + "/sub-1")
                .contentType(MediaType.APPLICATION_JSON).bodyValue("{\"active\":true}")
                .exchange().expectStatus().isForbidden();
        verify(service, never()).upsert(any(), anyBoolean(), any(), any());
    }

    // ── delete (SUPERADMIN + step-up) ────────────────────────────────────────────────
    @Test
    void delete_superadmin_withStepUp_reachesService() {
        when(stepUp.isSatisfied(any(), eq(TOKEN))).thenReturn(true);
        when(service.delete("sub-1")).thenReturn(Mono.just(1L));
        asSuperadmin().delete().uri(BASE + "/sub-1")
                .header(STEP_UP, TOKEN)
                .exchange().expectStatus().isOk()
                .expectBody().jsonPath("$.deleted").isEqualTo(1);
    }

    @Test
    void delete_admin_forbidden_neverReachesService() {
        asAdmin().delete().uri(BASE + "/sub-1")
                .header(STEP_UP, TOKEN).exchange().expectStatus().isForbidden();
        verify(service, never()).delete(any());
    }

    @Test
    void delete_missingStepUp_mfaDark_403_neverReachesService() {
        when(stepUp.isSatisfied(any(), any())).thenReturn(false);
        asSuperadmin().delete().uri(BASE + "/sub-1")
                .exchange().expectStatus().isForbidden();
        verify(service, never()).delete(any());
    }

    @Test
    void delete_unauthenticated_401() {
        web.delete().uri(BASE + "/sub-1").exchange().expectStatus().isUnauthorized();
        verify(service, never()).delete(any());
    }

    // ── a fresh Casdoor-MFA stamp satisfies step-up with no token, consumed single-use ─
    @Test
    void upsert_freshMfa_noToken_reachesService_andConsumesSingleUse() {
        when(stepUp.isSatisfied(any(), any())).thenReturn(false);   // token leg never satisfies
        when(mfaStepUp.isFresh(eq("bff_sess1"))).thenReturn(Mono.just(true));
        when(service.upsert(eq("sub-1"), eq(true), any(), any()))
                .thenReturn(Mono.just(ent("sub-1", true)));
        asSuperadmin().put().uri(BASE + "/sub-1")
                .cookie("bff_session", "bff_sess1").contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"active\":true}")
                .exchange().expectStatus().isOk();
        verify(service).upsert(eq("sub-1"), eq(true), any(), any());
        verify(mfaStepUp).consume(eq("bff_sess1"));
    }

    /**
     * The 403s above are satisfiable by the COARSE /bff/superadmin/** gate alone, so they cannot
     * detect a dropped per-method annotation. Every endpoint must carry its own
     * @PreAuthorize("hasRole('SUPERADMIN')") — pinned here (also pinned cross-controller in
     * {@link PhoneFleetOwnerControllerTest}).
     */
    @Test
    void everyEndpoint_carriesItsOwnSuperadminPreAuthorize() {
        int mappings = 0;
        for (var m : FleetEntitlementSuperadminController.class.getDeclaredMethods()) {
            boolean isMapping =
                    m.isAnnotationPresent(org.springframework.web.bind.annotation.GetMapping.class)
                 || m.isAnnotationPresent(org.springframework.web.bind.annotation.PutMapping.class)
                 || m.isAnnotationPresent(org.springframework.web.bind.annotation.DeleteMapping.class);
            if (!isMapping) {
                continue;
            }
            mappings++;
            var pa = m.getAnnotation(org.springframework.security.access.prepost.PreAuthorize.class);
            org.assertj.core.api.Assertions.assertThat(pa)
                    .as("%s must carry @PreAuthorize", m.getName()).isNotNull();
            org.assertj.core.api.Assertions.assertThat(pa.value())
                    .as("%s must require SUPERADMIN", m.getName())
                    .contains("hasRole('SUPERADMIN')");
        }
        org.assertj.core.api.Assertions.assertThat(mappings).isGreaterThan(0);
    }
}
