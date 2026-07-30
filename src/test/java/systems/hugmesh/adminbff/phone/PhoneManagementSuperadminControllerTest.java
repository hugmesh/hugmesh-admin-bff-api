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
import reactor.core.publisher.Mono;
import systems.hugmesh.adminbff.config.SecurityConfig;
import systems.hugmesh.adminbff.web.ApiExceptionHandler;
import systems.hugmesh.adminbff.web.ValidationExceptionHandler;
import systems.hugmesh.commons.security.DomainRegistry;
import systems.hugmesh.commons.web.ApiException;

import java.time.Instant;

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
 * The phone MANAGEMENT + LOCKOUT mutation role matrix + step-up gate — the acceptance bar for
 * the SUPERADMIN-only, step-up-gated boundary on the three {@code /bff/superadmin/phone-devices}
 * mutations. {@code @WebFluxTest} + the real {@link SecurityConfig} so BOTH the coarse
 * {@code /bff/superadmin/**} path gate AND the per-method {@code @PreAuthorize} run; the service
 * + gates are mocked so the controller's REFUSALS are proven to happen BEFORE the service.
 *
 * <ul>
 *   <li>SUPERADMIN + step-up &rarr; each mutation reaches the service and returns the device;</li>
 *   <li>ADMIN / MOD / USER &rarr; 403 on every mutation, service NEVER called;</li>
 *   <li>unauthenticated &rarr; 401;</li>
 *   <li>SUPERADMIN with NO step-up (MFA dark) &rarr; 403 requires step-up, service NEVER called;</li>
 *   <li>a fresh Casdoor-MFA stamp satisfies step-up with no token, and is consumed single-use;</li>
 *   <li>the service's 409 (BYOD lock) and 404 (unknown device) surface with their status.</li>
 * </ul>
 */
@WebFluxTest(controllers = PhoneManagementSuperadminController.class)
@Import({SecurityConfig.class, DomainRegistry.class, ValidationExceptionHandler.class, ApiExceptionHandler.class})
class PhoneManagementSuperadminControllerTest {

    private static final String STEP_UP = PhoneLockStepUpGate.STEP_UP_HEADER;
    private static final String TOKEN = "good-token";

    @Autowired ApplicationContext context;

    WebTestClient web;

    @MockitoBean PhoneManagementService service;
    @MockitoBean PhoneLockStepUpGate stepUp;
    @MockitoBean systems.hugmesh.authcore.casdoor.MfaStepUpService mfaStepUp;
    @MockitoBean ReactiveJwtDecoder jwtDecoder;

    @BeforeEach
    void setUp() {
        web = WebTestClient.bindToApplicationContext(context).apply(springSecurity()).build();
    }

    @BeforeEach
    void mfaDarkByDefault() {
        // MFA leg ships DARK: no fresh stamp -> only the workload step-up token leg satisfies.
        when(mfaStepUp.isFresh(any())).thenReturn(Mono.just(false));
        when(mfaStepUp.consume(any())).thenReturn(Mono.empty());
        when(stepUp.isSatisfied(anyString(), any(), anyBoolean()))
                .thenAnswer(inv -> inv.<Boolean>getArgument(2)
                        || stepUp.isSatisfied(inv.getArgument(0), inv.getArgument(1)));
    }

    private static PhoneDevice phone(String deviceId, String mode, String lockState) {
        return new PhoneDevice("pd-1", deviceId, "phone", null, "oriole", null, null, null,
                null, null, null, "phone-host", null, null, false, null, null, false, null,
                null, null, null, null, null, null, null, null, Instant.now(), Instant.now(),
                1L, mode, lockState, "degraded", 1L, "r", "sa", Instant.now(), null, null,
                "headwind", null);
    }

    private static PhoneDevice ownedPhone(String deviceId, String owner, String domain) {
        return new PhoneDevice("pd-1", deviceId, "phone", null, "oriole", null, null, null,
                null, null, null, "phone-host", null, null, false, null, null, false, null,
                null, null, null, null, null, null, null, null, Instant.now(), Instant.now(),
                1L, "mesh_owned", "unlocked", "degraded", 1L, "r", "sa", Instant.now(),
                owner, domain, "headwind", null);
    }

    private WebTestClient asSuperadmin() {
        return web.mutateWith(mockJwt().authorities(
                new SimpleGrantedAuthority("ROLE_USER"), new SimpleGrantedAuthority("ROLE_SUPERADMIN")));
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

    // ── SUPERADMIN + step-up: each mutation reaches the service ──────────────────────
    @Test
    void setManagement_superadmin_withStepUp_ok() {
        when(stepUp.isSatisfied(any(), eq(TOKEN))).thenReturn(true);
        when(service.setManagementMode(eq("phone-1"), eq("mesh_owned"), any()))
                .thenReturn(Mono.just(phone("phone-1", "mesh_owned", "unlocked")));
        asSuperadmin().put().uri("/bff/superadmin/phone-devices/phone-1/management")
                .header(STEP_UP, TOKEN).contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"mode\":\"mesh_owned\"}")
                .exchange().expectStatus().isOk()
                .expectBody().jsonPath("$.managementMode").isEqualTo("mesh_owned");
    }

    @Test
    void lock_superadmin_withStepUp_ok() {
        when(stepUp.isSatisfied(any(), eq(TOKEN))).thenReturn(true);
        when(service.lock(eq("phone-1"), any(), any()))
                .thenReturn(Mono.just(phone("phone-1", "mesh_owned", "locked")));
        asSuperadmin().post().uri("/bff/superadmin/phone-devices/phone-1/lock")
                .header(STEP_UP, TOKEN).contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"reason\":\"stolen\"}")
                .exchange().expectStatus().isOk()
                .expectBody().jsonPath("$.lockState").isEqualTo("locked");
    }

    @Test
    void unlock_superadmin_withStepUp_ok() {
        when(stepUp.isSatisfied(any(), eq(TOKEN))).thenReturn(true);
        when(service.unlock(eq("phone-1"), any()))
                .thenReturn(Mono.just(phone("phone-1", "mesh_owned", "unlocked")));
        asSuperadmin().post().uri("/bff/superadmin/phone-devices/phone-1/unlock")
                .header(STEP_UP, TOKEN)
                .exchange().expectStatus().isOk()
                .expectBody().jsonPath("$.lockState").isEqualTo("unlocked");
    }

    // ── owner assignment (changeset 305; SUPERADMIN + step-up) ───────────────────────
    @Test
    void setOwner_superadmin_withStepUp_ok() {
        when(stepUp.isSatisfied(any(), eq(TOKEN))).thenReturn(true);
        when(service.setOwner(eq("phone-1"), eq("alice-subject"), eq("acme.hugmesh.systems"), any()))
                .thenReturn(Mono.just(ownedPhone("phone-1", "alice-subject", "acme.hugmesh.systems")));
        asSuperadmin().put().uri("/bff/superadmin/phone-devices/phone-1/owner")
                .header(STEP_UP, TOKEN).contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"physicalOwner\":\"alice-subject\",\"ownerDomain\":\"acme.hugmesh.systems\"}")
                .exchange().expectStatus().isOk()
                .expectBody()
                .jsonPath("$.physicalOwner").isEqualTo("alice-subject")
                .jsonPath("$.ownerDomain").isEqualTo("acme.hugmesh.systems");
    }

    @Test
    void setOwner_admin_forbidden_neverReachService() {
        asAdmin().put().uri("/bff/superadmin/phone-devices/phone-1/owner")
                .header(STEP_UP, TOKEN).contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"physicalOwner\":\"alice-subject\",\"ownerDomain\":\"acme.hugmesh.systems\"}")
                .exchange().expectStatus().isForbidden();
        verify(service, never()).setOwner(any(), any(), any(), any());
    }

    @Test
    void setOwner_missingStepUp_mfaDark_403_neverReachService() {
        when(stepUp.isSatisfied(any(), any())).thenReturn(false);
        asSuperadmin().put().uri("/bff/superadmin/phone-devices/phone-1/owner")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"physicalOwner\":\"alice-subject\",\"ownerDomain\":\"acme.hugmesh.systems\"}")
                .exchange().expectStatus().isForbidden();
        verify(service, never()).setOwner(any(), any(), any(), any());
    }

    // ── ADMIN / MOD / USER: 403 on every mutation, service NEVER called ──────────────
    @Test
    void mutations_admin_forbidden_neverReachService() {
        asAdmin().put().uri("/bff/superadmin/phone-devices/phone-1/management")
                .header(STEP_UP, TOKEN).contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"mode\":\"mesh_owned\"}").exchange().expectStatus().isForbidden();
        asAdmin().post().uri("/bff/superadmin/phone-devices/phone-1/lock")
                .header(STEP_UP, TOKEN).contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"reason\":\"x\"}").exchange().expectStatus().isForbidden();
        asAdmin().post().uri("/bff/superadmin/phone-devices/phone-1/unlock")
                .header(STEP_UP, TOKEN).exchange().expectStatus().isForbidden();
        verify(service, never()).setManagementMode(any(), any(), any());
        verify(service, never()).lock(any(), any(), any());
        verify(service, never()).unlock(any(), any());
    }

    @Test
    void mutations_modAndUser_forbidden() {
        asMod().post().uri("/bff/superadmin/phone-devices/phone-1/lock")
                .header(STEP_UP, TOKEN).contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"reason\":\"x\"}").exchange().expectStatus().isForbidden();
        asUser().post().uri("/bff/superadmin/phone-devices/phone-1/unlock")
                .header(STEP_UP, TOKEN).exchange().expectStatus().isForbidden();
        verify(service, never()).lock(any(), any(), any());
        verify(service, never()).unlock(any(), any());
    }

    @Test
    void mutations_unauthenticated_401() {
        web.post().uri("/bff/superadmin/phone-devices/phone-1/unlock")
                .exchange().expectStatus().isUnauthorized();
        verify(service, never()).unlock(any(), any());
    }

    // ── step-up gate ─────────────────────────────────────────────────────────────────
    @Test
    void lock_missingStepUp_mfaDark_403_neverReachesService() {
        when(stepUp.isSatisfied(any(), any())).thenReturn(false);
        asSuperadmin().post().uri("/bff/superadmin/phone-devices/phone-1/lock")
                .contentType(MediaType.APPLICATION_JSON).bodyValue("{\"reason\":\"x\"}")
                .exchange().expectStatus().isForbidden();
        verify(service, never()).lock(any(), any(), any());
    }

    @Test
    void lock_invalidStepUp_403() {
        when(stepUp.isSatisfied(any(), eq("bad"))).thenReturn(false);
        asSuperadmin().post().uri("/bff/superadmin/phone-devices/phone-1/lock")
                .header(STEP_UP, "bad").contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"reason\":\"x\"}")
                .exchange().expectStatus().isForbidden();
        verify(service, never()).lock(any(), any(), any());
    }

    @Test
    void lock_freshMfa_noToken_reachesService_andConsumesSingleUse() {
        when(stepUp.isSatisfied(any(), any())).thenReturn(false);   // token leg never satisfies
        when(mfaStepUp.isFresh(eq("bff_sess1"))).thenReturn(Mono.just(true));
        when(service.lock(eq("phone-1"), any(), any()))
                .thenReturn(Mono.just(phone("phone-1", "mesh_owned", "locked")));
        asSuperadmin().post().uri("/bff/superadmin/phone-devices/phone-1/lock")
                .cookie("bff_session", "bff_sess1").contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"reason\":\"x\"}")
                .exchange().expectStatus().isOk();
        verify(service).lock(eq("phone-1"), any(), any());
        verify(mfaStepUp).consume(eq("bff_sess1"));
    }

    // ── service errors surface with their status ─────────────────────────────────────
    @Test
    void lock_byod_conflict_surfacesAs409() {
        when(stepUp.isSatisfied(any(), eq(TOKEN))).thenReturn(true);
        when(service.lock(eq("phone-byod"), any(), any()))
                .thenReturn(Mono.error(ApiException.conflict("phone 'phone-byod' is not a managed device")));
        asSuperadmin().post().uri("/bff/superadmin/phone-devices/phone-byod/lock")
                .header(STEP_UP, TOKEN).contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"reason\":\"x\"}")
                .exchange().expectStatus().isEqualTo(409);
    }

    @Test
    void unlock_unknownDevice_surfacesAs404() {
        when(stepUp.isSatisfied(any(), eq(TOKEN))).thenReturn(true);
        when(service.unlock(eq("nope"), any()))
                .thenReturn(Mono.error(ApiException.notFound("phone 'nope' not found")));
        asSuperadmin().post().uri("/bff/superadmin/phone-devices/nope/unlock")
                .header(STEP_UP, TOKEN)
                .exchange().expectStatus().isNotFound();
    }

    /**
     * The 403s above are satisfiable by the COARSE /bff/superadmin/** gate alone, so they
     * cannot detect a dropped per-method annotation. Every MUTATION handler (@PutMapping /
     * @PostMapping) must carry its own @PreAuthorize("hasRole('SUPERADMIN')") — pinned here.
     */
    @Test
    void everyMutation_carriesItsOwnSuperadminPreAuthorize() {
        for (var m : PhoneManagementSuperadminController.class.getDeclaredMethods()) {
            boolean isMutation =
                    m.isAnnotationPresent(org.springframework.web.bind.annotation.PutMapping.class)
                 || m.isAnnotationPresent(org.springframework.web.bind.annotation.PostMapping.class);
            if (!isMutation) {
                continue;
            }
            var pa = m.getAnnotation(org.springframework.security.access.prepost.PreAuthorize.class);
            org.assertj.core.api.Assertions.assertThat(pa)
                    .as("%s must carry @PreAuthorize (defence-in-depth)", m.getName())
                    .isNotNull();
            org.assertj.core.api.Assertions.assertThat(pa.value())
                    .as("%s must require SUPERADMIN", m.getName())
                    .contains("hasRole('SUPERADMIN')");
        }
    }
}
