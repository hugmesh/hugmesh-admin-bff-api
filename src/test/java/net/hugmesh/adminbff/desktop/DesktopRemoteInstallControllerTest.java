package net.hugmesh.adminbff.desktop;
import org.junit.jupiter.api.BeforeEach;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.boot.webflux.test.autoconfigure.WebFluxTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.reactive.server.WebTestClient;
import reactor.core.publisher.Mono;
import net.hugmesh.adminbff.config.SecurityConfig;
import net.hugmesh.adminbff.desktop.terminal.DeviceTerminalStepUpGate;
import net.hugmesh.commons.security.DomainRegistry;
import net.hugmesh.commons.security.PrincipalDomain;
import net.hugmesh.adminbff.web.ApiExceptionHandler;
import net.hugmesh.adminbff.web.ValidationExceptionHandler;

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
 * The REMOTE-INSTALL trigger controller — BFF-RI. Role matrix (ADMIN/SUPERADMIN ALLOW, MOD/USER
 * DENY) + the NEW step-up gate (missing/blank/invalid -> 403 even for an authorized ADMIN, no
 * service call) + the generic-403 anti-enumeration mapping + operator-from-JWT. The deep authz is
 * in {@link DesktopRemoteInstallServiceTest}.
 */
@WebFluxTest(controllers = DesktopRemoteInstallController.class)
@Import({SecurityConfig.class, DomainRegistry.class, ValidationExceptionHandler.class, ApiExceptionHandler.class})
class DesktopRemoteInstallControllerTest {

    private static final String STEP_UP = DeviceTerminalStepUpGate.STEP_UP_HEADER;
    private static final String TOKEN = "good-token";

    @Autowired ApplicationContext context;

    WebTestClient web;

    @BeforeEach
    void setUpWebTestClient() {
        web = WebTestClient.bindToApplicationContext(context).apply(springSecurity()).build();
    }

    @MockitoBean DesktopRemoteInstallService service;
    @MockitoBean DeviceTerminalStepUpGate stepUp;
    @MockitoBean net.hugmesh.authcore.casdoor.MfaStepUpService mfaStepUp;
    @MockitoBean ReactiveJwtDecoder jwtDecoder;

    @org.junit.jupiter.api.BeforeEach
    void mfaDarkByDefault() {
        // A5 MFA leg ships dark: no fresh MFA stamp, so only the workload step-up token leg
        // satisfies. The 3-arg unified gate delegates to the 2-arg token leg the tests stub.
        when(mfaStepUp.isFresh(any())).thenReturn(Mono.just(false));
        when(stepUp.isSatisfied(anyString(), any(), anyBoolean()))
                .thenAnswer(inv -> inv.<Boolean>getArgument(2)
                        || stepUp.isSatisfied(inv.getArgument(0), inv.getArgument(1)));
    }

    private WebTestClient asAdmin(String subject) {
        return web.mutateWith(mockJwt().jwt(j -> j.subject(subject)).authorities(
                new SimpleGrantedAuthority("ROLE_USER"), new SimpleGrantedAuthority("ROLE_ADMIN")));
    }

    private WebTestClient asMod() {
        return web.mutateWith(mockJwt().authorities(
                new SimpleGrantedAuthority("ROLE_USER"), new SimpleGrantedAuthority("ROLE_MOD")));
    }

    private WebTestClient asUser() {
        return web.mutateWith(mockJwt().authorities(new SimpleGrantedAuthority("ROLE_USER")));
    }

    private static final String URI = "/bff/admin/desktop/remote-install";
    private static final String BODY = "{\"deviceId\":\"dev-1\",\"appRef\":\"org.x.app\"}";

    @Test
    void remoteInstall_asAdmin_withStepUp_authorized_usesJwtSubjectAsOperator() {
        when(stepUp.isSatisfied(eq("admin-x"), eq(TOKEN))).thenReturn(true);
        when(service.remoteInstall(eq("admin-x"), eq("dev-1"), eq("org.x.app"), any(PrincipalDomain.class), any()))
                .thenReturn(Mono.just("{\"dark\":true}"));
        asAdmin("admin-x").post().uri(URI).header(STEP_UP, TOKEN)
                .contentType(MediaType.APPLICATION_JSON).bodyValue(BODY)
                .exchange().expectStatus().isOk();
        // operator is the JWT subject, never a body field.
        verify(service).remoteInstall(eq("admin-x"), eq("dev-1"), eq("org.x.app"), any(PrincipalDomain.class), any());
    }

    // ── step-up gate: missing / blank / invalid -> 403 even for an authorized ADMIN, no service call ──

    @Test
    void remoteInstall_missingStepUp_is403_noServiceCall() {
        when(stepUp.isSatisfied(any(), any())).thenReturn(false);
        asAdmin("admin-x").post().uri(URI)
                .contentType(MediaType.APPLICATION_JSON).bodyValue(BODY)
                .exchange().expectStatus().isForbidden();
        verify(service, never()).remoteInstall(anyString(), anyString(), anyString(), any(), any());
    }

    @Test
    void remoteInstall_blankStepUp_is403_noServiceCall() {
        when(stepUp.isSatisfied(any(), any())).thenReturn(false);
        asAdmin("admin-x").post().uri(URI).header(STEP_UP, "")
                .contentType(MediaType.APPLICATION_JSON).bodyValue(BODY)
                .exchange().expectStatus().isForbidden();
        verify(service, never()).remoteInstall(anyString(), anyString(), anyString(), any(), any());
    }

    @Test
    void remoteInstall_invalidStepUp_is403_noServiceCall() {
        when(stepUp.isSatisfied(eq("admin-x"), eq("bad"))).thenReturn(false);
        asAdmin("admin-x").post().uri(URI).header(STEP_UP, "bad")
                .contentType(MediaType.APPLICATION_JSON).bodyValue(BODY)
                .exchange().expectStatus().isForbidden();
        verify(service, never()).remoteInstall(anyString(), anyString(), anyString(), any(), any());
    }

    // ── anti-enumeration: device-targeting service denial -> ONE generic 403 ─────

    @Test
    void remoteInstall_serviceDenial_isGeneric403() {
        when(stepUp.isSatisfied(eq("admin-x"), eq(TOKEN))).thenReturn(true);
        when(service.remoteInstall(eq("admin-x"), eq("dev-1"), eq("org.x.app"), any(PrincipalDomain.class), any()))
                .thenReturn(Mono.error(new DesktopRemoteInstallService.RemoteInstallDeniedException(
                        "you hold no active SSH license for this device")));
        asAdmin("admin-x").post().uri(URI).header(STEP_UP, TOKEN)
                .contentType(MediaType.APPLICATION_JSON).bodyValue(BODY)
                .exchange().expectStatus().isForbidden()
                .expectBody().jsonPath("$.error").isEqualTo(DesktopRemoteInstallController.GENERIC_DENY);
    }

    // ── MOD / USER DENY (coarse gate beats step-up) ──────────────────────────────

    @Test
    void remoteInstall_asMod_isForbidden_andNeverTriggers() {
        asMod().post().uri(URI).header(STEP_UP, TOKEN)
                .contentType(MediaType.APPLICATION_JSON).bodyValue(BODY)
                .exchange().expectStatus().isForbidden();
        verify(service, never()).remoteInstall(anyString(), anyString(), anyString(), any(), any());
    }

    @Test
    void remoteInstall_asUser_isForbidden_andNeverTriggers() {
        asUser().post().uri(URI).header(STEP_UP, TOKEN)
                .contentType(MediaType.APPLICATION_JSON).bodyValue(BODY)
                .exchange().expectStatus().isForbidden();
        verify(service, never()).remoteInstall(anyString(), anyString(), anyString(), any(), any());
    }
}
