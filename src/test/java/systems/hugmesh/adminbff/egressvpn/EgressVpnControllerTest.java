package systems.hugmesh.adminbff.egressvpn;
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
import systems.hugmesh.adminbff.config.SecurityConfig;
import systems.hugmesh.commons.security.DomainRegistry;
import systems.hugmesh.commons.security.PrincipalDomain;
import systems.hugmesh.adminbff.web.ApiExceptionHandler;
import systems.hugmesh.adminbff.web.ValidationExceptionHandler;

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
 * The EGRESS-VPN controller role matrix — the acceptance bar for the
 * SUPERADMIN-mutate / ADMIN-read-only-own-domain / MOD-USER-deny boundary on
 * {@code /bff/admin/egress-vpn}. Mirrors {@code DeviceLicenseControllerTest}:
 * {@code @WebFluxTest} + the real {@link SecurityConfig} so the coarse path gate
 * ({@code hasAnyRole ADMIN,SUPERADMIN}) AND the per-method {@code @PreAuthorize} run.
 *
 * <ul>
 *   <li>SUPERADMIN write ALLOW (import / revoke / assign node / assign domain / unassign).</li>
 *   <li>ADMIN write DENY (403) + never reaches the service.</li>
 *   <li>ADMIN read ALLOW at the coarse gate (the own-domain wall is the service scope
 *       branch, exercised in {@link EgressVpnServiceDomainScopeTest}).</li>
 *   <li>MOD / USER DENY (403) on read AND write.</li>
 *   <li>a malformed config import surfaces as a 422.</li>
 * </ul>
 */
@WebFluxTest(controllers = EgressVpnController.class)
@Import({SecurityConfig.class, DomainRegistry.class, ValidationExceptionHandler.class, ApiExceptionHandler.class})
class EgressVpnControllerTest {

    @Autowired ApplicationContext context;

    WebTestClient web;

    @BeforeEach
    void setUpWebTestClient() {
        web = WebTestClient.bindToApplicationContext(context).apply(springSecurity()).build();
    }

    @MockitoBean EgressVpnService vpn;
    @MockitoBean VpnExportService export;
    @MockitoBean ReactiveJwtDecoder jwtDecoder;

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

    private static VpnConfig configSample() {
        return new VpnConfig("cfg-1", "brandx", "proton-us", VpnConfig.KIND_WIREGUARD,
                "protonvpn", "1.2.3.4:51820", "ref-1", VpnConfig.STATE_ACTIVE, "root",
                Instant.now(), null, null, VpnConfig.PROP_PENDING, 1L);
    }

    private static VpnNodeAssignment assignmentSample() {
        return new VpnNodeAssignment("asg-1", "cfg-1", VpnNodeAssignment.SCOPE_DEVICE, "fp-ok",
                null, "coturn", VpnNodeAssignment.STATE_ACTIVE, "root", Instant.now(), null, null,
                "brandx", VpnNodeAssignment.PROP_PENDING, 1L);
    }

    private static final String IMPORT_BODY = "{"
            + "\"domain\":\"brandx\",\"name\":\"proton-us\",\"provider\":\"protonvpn\","
            + "\"config\":\"[Interface]\\nPrivateKey = s\\n[Peer]\\nPublicKey = p\\nEndpoint = 1.2.3.4:51820\\n\"}";

    // ── SUPERADMIN write ALLOW ──────────────────────────────────────────────────

    @Test
    void importConfig_asSuperadmin_isAllowed() {
        when(vpn.importConfig(eq("brandx"), eq("proton-us"), anyString(), anyString(), anyString(), anyString()))
                .thenReturn(Mono.just(configSample()));
        asSuperadmin().post().uri("/bff/admin/egress-vpn/configs")
                .contentType(MediaType.APPLICATION_JSON).bodyValue(IMPORT_BODY)
                .exchange().expectStatus().isOk()
                .expectBody().jsonPath("$.id").isEqualTo("cfg-1")
                .jsonPath("$.kind").isEqualTo("wireguard");
        verify(vpn).importConfig(eq("brandx"), eq("proton-us"), anyString(), anyString(), anyString(), anyString());
    }

    @Test
    void revokeConfig_asSuperadmin_isAllowed() {
        when(vpn.revokeConfig(eq("cfg-1"), anyString(), any())).thenReturn(Mono.just(1L));
        asSuperadmin().delete().uri("/bff/admin/egress-vpn/configs/cfg-1")
                .exchange().expectStatus().isOk()
                .expectBody().jsonPath("$.revoked").isEqualTo(1);
        verify(vpn).revokeConfig(eq("cfg-1"), anyString(), any());
    }

    @Test
    void assignNode_asSuperadmin_isAllowed() {
        when(vpn.assignNode(eq("cfg-1"), eq("fp-ok"), any(), anyString()))
                .thenReturn(Mono.just(assignmentSample()));
        asSuperadmin().post().uri("/bff/admin/egress-vpn/configs/cfg-1/assign/node/fp-ok")
                .contentType(MediaType.APPLICATION_JSON).bodyValue("{\"serviceSlug\":\"coturn\"}")
                .exchange().expectStatus().isOk()
                .expectBody().jsonPath("$.scopeType").isEqualTo("DEVICE");
        verify(vpn).assignNode(eq("cfg-1"), eq("fp-ok"), eq("coturn"), anyString());
    }

    @Test
    void assignDomain_asSuperadmin_isAllowed() {
        when(vpn.assignDomain(eq("cfg-1"), eq("brandx"), any(), anyString()))
                .thenReturn(Mono.just(assignmentSample()));
        asSuperadmin().post().uri("/bff/admin/egress-vpn/configs/cfg-1/assign/domain/brandx")
                .exchange().expectStatus().isOk();
        verify(vpn).assignDomain(eq("cfg-1"), eq("brandx"), any(), anyString());
    }

    @Test
    void revokeAssignment_asSuperadmin_isAllowed() {
        when(vpn.revokeAssignment(eq("asg-1"), anyString(), any())).thenReturn(Mono.just(1L));
        asSuperadmin().delete().uri("/bff/admin/egress-vpn/assignments/asg-1")
                .exchange().expectStatus().isOk();
        verify(vpn).revokeAssignment(eq("asg-1"), anyString(), any());
    }

    @Test
    void export_asSuperadmin_isAllowed() {
        VpnExportModels.SignedVpnExport signed = new VpnExportModels.SignedVpnExport(
                new VpnExportModels.VpnExportBody("fp-1", 1L,
                        java.util.List.of(new VpnExportModels.VpnEgressEntry(
                                "proton-us", "wireguard", "ref-1", "1.2.3.4:51820", java.util.List.of()))),
                "hash", "sig", "pub", true);
        when(export.exportNode(eq("fp-1"))).thenReturn(Mono.just(signed));
        asSuperadmin().get().uri("/bff/admin/egress-vpn/export?node=fp-1")
                .exchange().expectStatus().isOk()
                .expectBody().jsonPath("$.signed").isEqualTo(true)
                .jsonPath("$.body.node").isEqualTo("fp-1");
        verify(export).exportNode(eq("fp-1"));
    }

    @Test
    void export_asAdmin_isForbidden() {
        asAdmin().get().uri("/bff/admin/egress-vpn/export?node=fp-1")
                .exchange().expectStatus().isForbidden();
        verify(export, never()).exportNode(anyString());
    }

    @Test
    void export_asUser_isForbidden() {
        asUser().get().uri("/bff/admin/egress-vpn/export?node=fp-1")
                .exchange().expectStatus().isForbidden();
    }

    @Test
    void list_asSuperadmin_isAllowed() {
        when(vpn.listConfigs(any())).thenReturn(Flux.just(configSample()));
        when(vpn.listAssignments(any())).thenReturn(Flux.just(assignmentSample()));
        asSuperadmin().get().uri("/bff/admin/egress-vpn")
                .exchange().expectStatus().isOk()
                .expectBody().jsonPath("$.configs[0].id").isEqualTo("cfg-1")
                .jsonPath("$.assignments[0].id").isEqualTo("asg-1");
    }

    // ── ADMIN read ALLOW (own-domain wall is service-side) ──────────────────────

    @Test
    void list_asAdmin_isAllowed_atCoarseGate() {
        when(vpn.listConfigs(any())).thenReturn(Flux.empty());
        when(vpn.listAssignments(any())).thenReturn(Flux.empty());
        asAdmin().get().uri("/bff/admin/egress-vpn").exchange().expectStatus().isOk();
    }

    // ── ADMIN write DENY (403) + never writes ───────────────────────────────────

    @Test
    void importConfig_asAdmin_isForbidden_andNeverWrites() {
        asAdmin().post().uri("/bff/admin/egress-vpn/configs")
                .contentType(MediaType.APPLICATION_JSON).bodyValue(IMPORT_BODY)
                .exchange().expectStatus().isForbidden();
        verify(vpn, never()).importConfig(anyString(), anyString(), any(), anyString(), anyString(), anyString());
    }

    @Test
    void revokeConfig_asAdmin_isForbidden() {
        asAdmin().delete().uri("/bff/admin/egress-vpn/configs/cfg-1")
                .exchange().expectStatus().isForbidden();
        verify(vpn, never()).revokeConfig(anyString(), anyString(), any());
    }

    @Test
    void assignNode_asAdmin_isForbidden() {
        asAdmin().post().uri("/bff/admin/egress-vpn/configs/cfg-1/assign/node/fp-ok")
                .contentType(MediaType.APPLICATION_JSON).bodyValue("{}")
                .exchange().expectStatus().isForbidden();
        verify(vpn, never()).assignNode(anyString(), anyString(), any(), anyString());
    }

    // ── MOD / USER DENY on read AND write ───────────────────────────────────────

    @Test
    void list_asMod_isForbidden() {
        asMod().get().uri("/bff/admin/egress-vpn").exchange().expectStatus().isForbidden();
    }

    @Test
    void list_asUser_isForbidden() {
        asUser().get().uri("/bff/admin/egress-vpn").exchange().expectStatus().isForbidden();
    }

    @Test
    void importConfig_asUser_isForbidden() {
        asUser().post().uri("/bff/admin/egress-vpn/configs")
                .contentType(MediaType.APPLICATION_JSON).bodyValue(IMPORT_BODY)
                .exchange().expectStatus().isForbidden();
    }

    // ── 422 on a malformed config (service throws IllegalArgumentException) ──────

    @Test
    void importConfig_malformed_is422() {
        when(vpn.importConfig(anyString(), anyString(), any(), anyString(), anyString(), anyString()))
                .thenReturn(Mono.error(new IllegalArgumentException("unrecognised VPN config")));
        asSuperadmin().post().uri("/bff/admin/egress-vpn/configs")
                .contentType(MediaType.APPLICATION_JSON).bodyValue(IMPORT_BODY)
                .exchange().expectStatus().isEqualTo(org.springframework.http.HttpStatus.UNPROCESSABLE_ENTITY)
                .expectBody().jsonPath("$.error").isEqualTo("unrecognised VPN config");
    }
}
