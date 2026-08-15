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
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import net.hugmesh.adminbff.config.SecurityConfig;
import net.hugmesh.commons.security.DomainRegistry;
import net.hugmesh.commons.security.PrincipalDomain;
import net.hugmesh.adminbff.web.ApiExceptionHandler;
import net.hugmesh.adminbff.web.ValidationExceptionHandler;

import java.time.Instant;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.mockJwt;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.springSecurity;

/**
 * The DESKTOP SUDO grant controller role matrix — ADMIN/SUPERADMIN ALLOW (grant/revoke/list),
 * MOD/USER DENY, and the SUPERADMIN-owned-device service guard -> 422.
 */
@WebFluxTest(controllers = DesktopSudoAdminController.class)
@Import({SecurityConfig.class, DomainRegistry.class, ValidationExceptionHandler.class, ApiExceptionHandler.class})
class DesktopSudoAdminControllerTest {

    @Autowired ApplicationContext context;

    WebTestClient web;

    @BeforeEach
    void setUpWebTestClient() {
        web = WebTestClient.bindToApplicationContext(context).apply(springSecurity()).build();
    }

    @MockitoBean DesktopSudoGrantService service;
    @MockitoBean ReactiveJwtDecoder jwtDecoder;
    @MockitoBean net.hugmesh.authcore.provision.GatewayRevocationClient revocations;

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

    private static DesktopSudoGrant grant() {
        return new DesktopSudoGrant("g1", "alice", "dev-1", DesktopSudoGrant.STATE_ACTIVE,
                "root", Instant.now(), null, null, "brandx", DesktopSudoGrant.PROP_PENDING, 1L);
    }

    private static final String GRANT_BODY = "{\"subject\":\"alice\",\"deviceId\":\"dev-1\"}";

    @Test
    void grant_asAdmin_isAllowed() {
        when(service.grant(eq("alice"), eq("dev-1"), anyString(), any(PrincipalDomain.class)))
                .thenReturn(Mono.just(grant()));
        asAdmin().post().uri("/bff/admin/desktop/sudo/grant")
                .contentType(MediaType.APPLICATION_JSON).bodyValue(GRANT_BODY)
                .exchange().expectStatus().isOk()
                .expectBody().jsonPath("$.subject").isEqualTo("alice");
        // the acting admin's scope is threaded in (own-domain wall, parity with revoke/list).
        verify(service).grant(eq("alice"), eq("dev-1"), anyString(), any(PrincipalDomain.class));
    }

    @Test
    void revoke_asAdmin_isAllowed() {
        when(service.revoke(eq("g1"), anyString(), any(PrincipalDomain.class))).thenReturn(Mono.just(1L));
        asAdmin().delete().uri("/bff/admin/desktop/sudo/g1")
                .exchange().expectStatus().isOk()
                .expectBody().jsonPath("$.revoked").isEqualTo(1);
    }

    @Test
    void list_asAdmin_isAllowed() {
        when(service.list(any(PrincipalDomain.class))).thenReturn(Flux.just(grant()));
        asAdmin().get().uri("/bff/admin/desktop/sudo").exchange().expectStatus().isOk();
    }

    @Test
    void grant_onSuperadminOwnedDevice_is422() {
        when(service.grant(eq("alice"), eq("dev-1"), anyString(), any(PrincipalDomain.class)))
                .thenReturn(Mono.error(new IllegalArgumentException(
                        "cannot grant desktop sudo on a SUPERADMIN-owned device")));
        asAdmin().post().uri("/bff/admin/desktop/sudo/grant")
                .contentType(MediaType.APPLICATION_JSON).bodyValue(GRANT_BODY)
                .exchange().expectStatus().isEqualTo(422)
                .expectBody().jsonPath("$.error").value(
                        org.hamcrest.Matchers.containsString("SUPERADMIN-owned"));
    }

    @Test
    void grant_noActiveSshLicenseDenialFromService_is403() {
        // the device-ssh-license precondition surfaces as a 403 (RemoteInstallDeniedException
        // mapping), the SAME status family as the remote-install license denial — distinct from
        // the 422 own-domain/superadmin-owned denials.
        when(service.grant(eq("alice"), eq("dev-1"), anyString(), any(PrincipalDomain.class)))
                .thenReturn(Mono.error(new DesktopRemoteInstallService.RemoteInstallDeniedException(
                        "you hold no active SSH license for this device")));
        asAdmin().post().uri("/bff/admin/desktop/sudo/grant")
                .contentType(MediaType.APPLICATION_JSON).bodyValue(GRANT_BODY)
                .exchange().expectStatus().isForbidden()
                .expectBody().jsonPath("$.error").value(
                        org.hamcrest.Matchers.containsString("no active SSH license"));
    }

    @Test
    void grant_crossDomainDenialFromService_is422() {
        // the own-domain wall surfaces as the same clean 422 (IllegalArgumentException mapping).
        when(service.grant(eq("alice"), eq("dev-1"), anyString(), any(PrincipalDomain.class)))
                .thenReturn(Mono.error(new IllegalArgumentException("device is not in your domain")));
        asAdmin().post().uri("/bff/admin/desktop/sudo/grant")
                .contentType(MediaType.APPLICATION_JSON).bodyValue(GRANT_BODY)
                .exchange().expectStatus().isEqualTo(422)
                .expectBody().jsonPath("$.error").value(
                        org.hamcrest.Matchers.containsString("not in your domain"));
    }

    // ── MOD / USER DENY ──────────────────────────────────────────────────────────

    @Test
    void grant_asMod_isForbidden_andNeverWrites() {
        asMod().post().uri("/bff/admin/desktop/sudo/grant")
                .contentType(MediaType.APPLICATION_JSON).bodyValue(GRANT_BODY)
                .exchange().expectStatus().isForbidden();
        verify(service, never()).grant(anyString(), anyString(), anyString(), any());
    }

    @Test
    void revoke_asUser_isForbidden_andNeverWrites() {
        asUser().delete().uri("/bff/admin/desktop/sudo/g1")
                .exchange().expectStatus().isForbidden();
        verify(service, never()).revoke(anyString(), anyString(), any());
    }

    @Test
    void list_asUser_isForbidden() {
        asUser().get().uri("/bff/admin/desktop/sudo").exchange().expectStatus().isForbidden();
    }
}
