package net.hugmesh.adminbff.desktop;
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
import reactor.core.publisher.Mono;
import net.hugmesh.adminbff.config.SecurityConfig;
import net.hugmesh.adminbff.desktop.terminal.DeviceSshTerminalWebSocketHandler;
import net.hugmesh.adminbff.desktop.terminal.DeviceTerminalProperties;
import net.hugmesh.commons.security.DomainRegistry;
import net.hugmesh.commons.security.PrincipalDomain;
import net.hugmesh.adminbff.web.ApiExceptionHandler;
import net.hugmesh.adminbff.web.ValidationExceptionHandler;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.mockJwt;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.springSecurity;

/**
 * The SSH-TERMINAL pre-WS DESCRIPTOR controller — BFF-DESCRIPTOR. ADMIN/SUPERADMIN reach the
 * descriptor carrying the REAL live WS path + stepUpRequired + the dark flag; MOD/USER → 403,
 * unauthenticated → 401; every device-targeting service denial collapses to ONE generic 403
 * (anti-enumeration). The contract-pin test asserts {@code wsPath} matches the live handler's
 * {@code WS_PATH_PREFIX} so the UI/BFF path cannot drift. The deep authz is in
 * {@link DesktopRemoteInstallServiceTest}.
 *
 * <p>The {@code app.device-terminal.enabled} property defaults FALSE here (no property set), so the
 * descriptor's {@code dark} is true — the ships-dark structural assertion.
 */
@WebFluxTest(controllers = DesktopSshTerminalController.class)
@Import({SecurityConfig.class, DomainRegistry.class, DeviceTerminalProperties.class,
        ValidationExceptionHandler.class, ApiExceptionHandler.class})
class DesktopSshTerminalControllerTest {

    @Autowired ApplicationContext context;

    WebTestClient web;

    @BeforeEach
    void setUpWebTestClient() {
        web = WebTestClient.bindToApplicationContext(context).apply(springSecurity()).build();
    }

    @MockitoBean DesktopRemoteInstallService remoteInstall;
    @MockitoBean ReactiveJwtDecoder jwtDecoder;

    private WebTestClient asAdmin(String subject) {
        return web.mutateWith(mockJwt().jwt(j -> j.subject(subject)).authorities(
                new SimpleGrantedAuthority("ROLE_USER"), new SimpleGrantedAuthority("ROLE_ADMIN")));
    }

    private WebTestClient asSuperadmin(String subject) {
        return web.mutateWith(mockJwt().jwt(j -> j.subject(subject)).authorities(
                new SimpleGrantedAuthority("ROLE_USER"), new SimpleGrantedAuthority("ROLE_SUPERADMIN")));
    }

    private WebTestClient asMod() {
        return web.mutateWith(mockJwt().authorities(
                new SimpleGrantedAuthority("ROLE_USER"), new SimpleGrantedAuthority("ROLE_MOD")));
    }

    private WebTestClient asUser() {
        return web.mutateWith(mockJwt().authorities(new SimpleGrantedAuthority("ROLE_USER")));
    }

    private static final String URI = "/bff/admin/desktop/ssh-terminal/sessions?deviceId=dev-1";

    // ── ADMIN / SUPERADMIN reach (authorized -> descriptor with REAL wsPath, dark by default) ──

    @Test
    void openSession_asAdmin_authorized_returnsRealDescriptor_darkByDefault() {
        when(remoteInstall.authorizeTerminal(eq("admin-x"), eq("dev-1"), any(PrincipalDomain.class)))
                .thenReturn(Mono.empty());
        asAdmin("admin-x").post().uri(URI)
                .exchange().expectStatus().isOk()
                .expectBody()
                .jsonPath("$.deviceId").isEqualTo("dev-1")
                .jsonPath("$.dark").isEqualTo(true)               // app.device-terminal.enabled defaults false
                .jsonPath("$.stepUpRequired").isEqualTo(true)
                // CONTRACT PIN: the emitted wsPath MUST be the live handler's mount + deviceId.
                .jsonPath("$.wsPath").isEqualTo(
                        DeviceSshTerminalWebSocketHandler.WS_PATH_PREFIX + "dev-1");
        verify(remoteInstall).authorizeTerminal(eq("admin-x"), eq("dev-1"), any(PrincipalDomain.class));
    }

    @Test
    void openSession_asSuperadmin_authorized() {
        when(remoteInstall.authorizeTerminal(eq("super-1"), eq("dev-1"), any(PrincipalDomain.class)))
                .thenReturn(Mono.empty());
        asSuperadmin("super-1").post().uri(URI)
                .exchange().expectStatus().isOk()
                .expectBody().jsonPath("$.wsPath").isEqualTo(
                        DeviceSshTerminalWebSocketHandler.WS_PATH_PREFIX + "dev-1");
    }

    // ── anti-enumeration: every device-targeting denial -> ONE generic 403 ───────

    @Test
    void openSession_superadminOwnedDenial_isGeneric403() {
        when(remoteInstall.authorizeTerminal(eq("admin-x"), eq("dev-1"), any(PrincipalDomain.class)))
                .thenReturn(Mono.error(new DesktopRemoteInstallService.RemoteInstallDeniedException(
                        "cannot open an SSH terminal onto a SUPERADMIN-owned node")));
        asAdmin("admin-x").post().uri(URI)
                .exchange().expectStatus().isForbidden()
                .expectBody()
                // the SPECIFIC cause must NOT leak — generic message only.
                .jsonPath("$.error").isEqualTo(DesktopSshTerminalController.GENERIC_DENY);
    }

    @Test
    void openSession_crossDomainDenial_isSameGeneric403_asSuperadminOwned() {
        when(remoteInstall.authorizeTerminal(eq("admin-x"), eq("dev-1"), any(PrincipalDomain.class)))
                .thenReturn(Mono.error(new DesktopRemoteInstallService.RemoteInstallDeniedException(
                        "device is not in your domain")));
        asAdmin("admin-x").post().uri(URI)
                .exchange().expectStatus().isForbidden()
                .expectBody().jsonPath("$.error").isEqualTo(DesktopSshTerminalController.GENERIC_DENY);
    }

    @Test
    void openSession_noLicenseDenial_isSameGeneric403() {
        when(remoteInstall.authorizeTerminal(eq("admin-x"), eq("dev-1"), any(PrincipalDomain.class)))
                .thenReturn(Mono.error(new DesktopRemoteInstallService.RemoteInstallDeniedException(
                        "you hold no active SSH license for this device")));
        asAdmin("admin-x").post().uri(URI)
                .exchange().expectStatus().isForbidden()
                .expectBody().jsonPath("$.error").isEqualTo(DesktopSshTerminalController.GENERIC_DENY);
    }

    // ── MOD / USER -> 403, never authorizes ──────────────────────────────────────

    @Test
    void openSession_asMod_isForbidden_andNeverAuthorizes() {
        asMod().post().uri(URI).exchange().expectStatus().isForbidden();
        verify(remoteInstall, never()).authorizeTerminal(anyString(), anyString(), any());
    }

    @Test
    void openSession_asUser_isForbidden_andNeverAuthorizes() {
        asUser().post().uri(URI).exchange().expectStatus().isForbidden();
        verify(remoteInstall, never()).authorizeTerminal(anyString(), anyString(), any());
    }

    // ── unauthenticated -> 401 ────────────────────────────────────────────────────

    @Test
    void openSession_unauthenticated_is401() {
        web.post().uri(URI).exchange().expectStatus().isUnauthorized();
        verify(remoteInstall, never()).authorizeTerminal(anyString(), anyString(), any());
    }
}
