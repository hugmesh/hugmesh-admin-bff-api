package net.hugmesh.adminbff.sshterminal;
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
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import net.hugmesh.adminbff.config.SecurityConfig;
import net.hugmesh.adminbff.desktop.terminal.DeviceTerminalStepUpGate;
import net.hugmesh.commons.security.DomainRegistry;
import net.hugmesh.adminbff.web.ApiExceptionHandler;
import net.hugmesh.adminbff.web.ValidationExceptionHandler;

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
 * BFF-DIAL web-layer contract — SUPERADMIN-only dial management. The role matrix (SUPERADMIN ALLOW;
 * ADMIN/MOD/USER DENY, never calls the service), the step-up requirement on the mutations
 * (missing/blank → 403, no service call), the non-secret response (no key bytes), and the
 * service-exception → HTTP status mapping (dark 503 / unpinned 422 / not-found 404). The deep
 * lifecycle is in {@link DesktopDialServiceTest}.
 *
 * <p>The {@code mfaDarkByDefault()} setup proves DARK = byte-identical to the pre-existing
 * token-only behaviour (every test above it uses the workload-token leg); the dedicated
 * {@code *_freshMfa_*} tests below prove the co-equal fresh-MFA leg now also satisfies these two
 * SUPERADMIN mutations, matching {@code BackupAdminController} / {@code
 * DesktopRemoteInstallController} / {@code AdminSshKeyIssuanceController}.
 */
@WebFluxTest(controllers = DesktopDialAdminController.class)
@Import({SecurityConfig.class, DomainRegistry.class, ValidationExceptionHandler.class, ApiExceptionHandler.class})
class DesktopDialAdminControllerTest {

    private static final String STEP_UP = DeviceTerminalStepUpGate.STEP_UP_HEADER;
    private static final String TOKEN = "good-token";
    private static final String BASE = "/bff/superadmin/desktop/dials";

    @Autowired ApplicationContext context;

    WebTestClient web;

    @BeforeEach
    void setUpWebTestClient() {
        web = WebTestClient.bindToApplicationContext(context).apply(springSecurity()).build();
    }

    @MockitoBean DesktopDialService service;
    @MockitoBean DeviceTerminalStepUpGate stepUp;
    @MockitoBean net.hugmesh.authcore.casdoor.MfaStepUpService mfaStepUp;
    @MockitoBean ReactiveJwtDecoder jwtDecoder;
    @MockitoBean net.hugmesh.authcore.provision.GatewayRevocationClient revocations;

    @BeforeEach
    void mfaDarkByDefault() {
        // A5 MFA leg ships dark: no fresh MFA stamp by default, so only the workload step-up
        // token leg satisfies (today's behaviour). The 3-arg unified gate delegates to the 2-arg
        // token leg the individual tests stub.
        when(mfaStepUp.isFresh(any())).thenReturn(Mono.just(false));
        when(mfaStepUp.consume(any())).thenReturn(Mono.empty());
        when(stepUp.isSatisfied(anyString(), any(), anyBoolean()))
                .thenAnswer(inv -> inv.<Boolean>getArgument(2)
                        || stepUp.isSatisfied(inv.getArgument(0), inv.getArgument(1)));
    }

    private WebTestClient asSuperadmin(String subject) {
        return web.mutateWith(mockJwt().jwt(j -> j.subject(subject)).authorities(
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

    private static DeviceSshDial active(String deviceId, long gen) {
        return new DeviceSshDial("id-" + deviceId, deviceId, "snapops", "ssh-ed25519 AAAA",
                "SHA256:hostfp", "SHA256:dialfp", "vault://kv/dial/" + deviceId,
                "dial-key-" + deviceId, null, DeviceSshDial.STATUS_ACTIVE, gen, Instant.now(), Instant.now());
    }

    // ── list / get: SUPERADMIN ALLOW, non-secret ────────────────────────────────

    @Test
    void list_asSuperadmin_ok_nonSecret() {
        when(service.list(any())).thenReturn(Flux.just(active("dev-1", 2L)));
        asSuperadmin("super-1").get().uri(BASE)
                .exchange().expectStatus().isOk()
                .expectBody()
                .jsonPath("$[0].deviceId").isEqualTo("dev-1")
                .jsonPath("$[0].status").isEqualTo("ACTIVE")
                .jsonPath("$[0].vaultRef").isEqualTo("vault://kv/dial/dev-1");
    }

    @Test
    void list_asAdmin_403_neverCallsService() {
        asAdmin().get().uri(BASE).exchange().expectStatus().isForbidden();
        verify(service, never()).list(any());
    }

    @Test
    void get_asSuperadmin_ok() {
        when(service.findByDevice(eq("dev-1"))).thenReturn(Mono.just(active("dev-1", 2L)));
        asSuperadmin("super-1").get().uri(BASE + "/dev-1")
                .exchange().expectStatus().isOk()
                .expectBody().jsonPath("$.status").isEqualTo("ACTIVE");
    }

    @Test
    void get_absent_genericNotFound() {
        when(service.findByDevice(eq("ghost"))).thenReturn(Mono.empty());
        asSuperadmin("super-1").get().uri(BASE + "/ghost")
                .exchange().expectStatus().isNotFound()
                .expectBody().jsonPath("$.error").isEqualTo(DesktopDialAdminController.GENERIC_DIAL_NOT_FOUND);
    }

    // ── activate: role + step-up + status mapping ───────────────────────────────

    @Test
    void activate_asSuperadmin_withStepUp_ok() {
        when(stepUp.isSatisfied(eq("super-1"), eq(TOKEN))).thenReturn(true);
        when(service.activate(eq("dev-1"), eq("super-1"))).thenReturn(Mono.just(active("dev-1", 2L)));
        asSuperadmin("super-1").post().uri(BASE + "/dev-1/activate").header(STEP_UP, TOKEN)
                .exchange().expectStatus().isOk()
                .expectBody().jsonPath("$.status").isEqualTo("ACTIVE");
        verify(stepUp).consume(eq("super-1"));
    }

    @Test
    void activate_missingStepUp_403_noServiceCall() {
        when(stepUp.isSatisfied(any(), any())).thenReturn(false);
        asSuperadmin("super-1").post().uri(BASE + "/dev-1/activate")
                .exchange().expectStatus().isForbidden();
        verify(service, never()).activate(anyString(), anyString());
    }

    @Test
    void activate_asAdmin_403_noServiceCall() {
        asAdmin().post().uri(BASE + "/dev-1/activate").header(STEP_UP, TOKEN)
                .exchange().expectStatus().isForbidden();
        verify(service, never()).activate(anyString(), anyString());
    }

    @Test
    void activate_asMod_403() {
        asMod().post().uri(BASE + "/dev-1/activate").header(STEP_UP, TOKEN)
                .exchange().expectStatus().isForbidden();
    }

    @Test
    void activate_asUser_403() {
        asUser().post().uri(BASE + "/dev-1/activate").header(STEP_UP, TOKEN)
                .exchange().expectStatus().isForbidden();
    }

    @Test
    void activate_unpinned_422() {
        when(stepUp.isSatisfied(eq("super-1"), eq(TOKEN))).thenReturn(true);
        when(service.activate(eq("dev-1"), eq("super-1"))).thenReturn(Mono.error(
                new DesktopDialService.DialUnpinnedException("no pinned host_key_fp")));
        asSuperadmin("super-1").post().uri(BASE + "/dev-1/activate").header(STEP_UP, TOKEN)
                .exchange().expectStatus().isEqualTo(422);
    }

    @Test
    void activate_whileDark_503() {
        when(stepUp.isSatisfied(eq("super-1"), eq(TOKEN))).thenReturn(true);
        when(service.activate(eq("dev-1"), eq("super-1"))).thenReturn(Mono.error(
                new DesktopDialService.DialDarkException("ships dark")));
        asSuperadmin("super-1").post().uri(BASE + "/dev-1/activate").header(STEP_UP, TOKEN)
                .exchange().expectStatus().isEqualTo(503);
    }

    @Test
    void activate_absent_genericNotFound() {
        when(stepUp.isSatisfied(eq("super-1"), eq(TOKEN))).thenReturn(true);
        when(service.activate(eq("ghost"), eq("super-1"))).thenReturn(Mono.error(
                new DesktopDialService.DialNotFoundException("no row for device=ghost")));
        asSuperadmin("super-1").post().uri(BASE + "/ghost/activate").header(STEP_UP, TOKEN)
                .exchange().expectStatus().isNotFound()
                .expectBody().jsonPath("$.error").isEqualTo(DesktopDialAdminController.GENERIC_DIAL_NOT_FOUND);
    }

    // ── revoke: role + step-up ───────────────────────────────────────────────────

    @Test
    void revoke_asSuperadmin_withStepUp_ok() {
        when(stepUp.isSatisfied(eq("super-1"), eq(TOKEN))).thenReturn(true);
        when(service.revoke(eq("dev-1"), eq("super-1"))).thenReturn(Mono.just(
                new DeviceSshDial("id", "dev-1", "snapops", "k", "SHA256:h", "SHA256:d", "vault://x",
                        "sec", null, DeviceSshDial.STATUS_REVOKED, 3L, Instant.now(), Instant.now())));
        asSuperadmin("super-1").post().uri(BASE + "/dev-1/revoke").header(STEP_UP, TOKEN)
                .exchange().expectStatus().isOk()
                .expectBody().jsonPath("$.status").isEqualTo("REVOKED");
        verify(stepUp).consume(eq("super-1"));
    }

    @Test
    void revoke_missingStepUp_403_noServiceCall() {
        when(stepUp.isSatisfied(any(), any())).thenReturn(false);
        asSuperadmin("super-1").post().uri(BASE + "/dev-1/revoke")
                .exchange().expectStatus().isForbidden();
        verify(service, never()).revoke(anyString(), anyString());
    }

    @Test
    void revoke_asAdmin_403() {
        asAdmin().post().uri(BASE + "/dev-1/revoke").header(STEP_UP, TOKEN)
                .exchange().expectStatus().isForbidden();
        verify(service, never()).revoke(anyString(), anyString());
    }

    // ── A5 co-equal MFA step-up leg (parity with the other 4 gates) ─────────────

    @Test
    void activate_freshMfa_noWorkloadToken_ok_andConsumesSingleUse() {
        // No workload token (header absent) -> the 2-arg token leg is unsatisfied; only the
        // fresh MFA stamp can carry step-up. The bff_session cookie supplies the opaque session
        // token mfaStepUp.isFresh()/consume() key off of.
        when(stepUp.isSatisfied(any(), any())).thenReturn(false);
        when(mfaStepUp.isFresh(eq("bff_sess1"))).thenReturn(Mono.just(true));
        when(service.activate(eq("dev-1"), eq("super-1"))).thenReturn(Mono.just(active("dev-1", 2L)));
        asSuperadmin("super-1").post().uri(BASE + "/dev-1/activate")
                .cookie("bff_session", "bff_sess1")
                .exchange().expectStatus().isOk()
                .expectBody().jsonPath("$.status").isEqualTo("ACTIVE");
        verify(service).activate(eq("dev-1"), eq("super-1"));
        verify(mfaStepUp).consume(eq("bff_sess1"));
    }

    @Test
    void revoke_freshMfa_noWorkloadToken_ok_andConsumesSingleUse() {
        when(stepUp.isSatisfied(any(), any())).thenReturn(false);
        when(mfaStepUp.isFresh(eq("bff_sess1"))).thenReturn(Mono.just(true));
        when(service.revoke(eq("dev-1"), eq("super-1"))).thenReturn(Mono.just(
                new DeviceSshDial("id", "dev-1", "snapops", "k", "SHA256:h", "SHA256:d", "vault://x",
                        "sec", null, DeviceSshDial.STATUS_REVOKED, 3L, Instant.now(), Instant.now())));
        asSuperadmin("super-1").post().uri(BASE + "/dev-1/revoke")
                .cookie("bff_session", "bff_sess1")
                .exchange().expectStatus().isOk()
                .expectBody().jsonPath("$.status").isEqualTo("REVOKED");
        verify(service).revoke(eq("dev-1"), eq("super-1"));
        verify(mfaStepUp).consume(eq("bff_sess1"));
    }
}
