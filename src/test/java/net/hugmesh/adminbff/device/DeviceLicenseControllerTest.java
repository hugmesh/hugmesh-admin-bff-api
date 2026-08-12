package net.hugmesh.adminbff.device;
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
import java.util.List;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.mockJwt;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.springSecurity;

/**
 * The DEVICE-LICENSE REGISTRY controller role matrix — the acceptance bar for the
 * SUPERADMIN-mutate / ADMIN-read-only-own-domain / MOD-USER-deny boundary on
 * {@code /bff/admin/device-licenses}. Mirrors {@code AdminControllerAccessRolesTest}:
 * {@code @WebFluxTest} + the real {@link SecurityConfig} so the coarse path gate
 * ({@code hasAnyRole ADMIN,SUPERADMIN}) AND the per-method {@code @PreAuthorize} run.
 *
 * <ul>
 *   <li>SUPERADMIN write ALLOW (register / grant device / grant domain / revoke /
 *       de-register / export).</li>
 *   <li>ADMIN write DENY (403) + never reaches the service.</li>
 *   <li>ADMIN read ALLOW at the coarse gate (the own-domain wall is the service scope
 *       branch, exercised in {@link SshLicenseServiceDomainScopeTest}).</li>
 *   <li>MOD / USER DENY (403) on read AND write.</li>
 *   <li>ADMIN export DENY (403) — the signed export is SUPERADMIN | internal-mTLS only.</li>
 * </ul>
 */
@WebFluxTest(controllers = DeviceLicenseController.class)
@Import({SecurityConfig.class, DomainRegistry.class, ValidationExceptionHandler.class, ApiExceptionHandler.class})
class DeviceLicenseControllerTest {

    @Autowired ApplicationContext context;

    WebTestClient web;

    @BeforeEach
    void setUpWebTestClient() {
        web = WebTestClient.bindToApplicationContext(context).apply(springSecurity()).build();
    }

    @MockitoBean DeviceRegistryService devices;
    @MockitoBean SshLicenseService licenses;
    @MockitoBean DeviceRegistryExportService export;
    @MockitoBean DevicePendingService pending;
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

    private static Device deviceSample() {
        return new Device("dev-1", "fp-aaa", "brandx-node-1", "tn-1",
                Device.IMAGE_MESH_EXTENSION, "rpi5", Device.OWNER_ADMIN, "alice@brandx",
                "brandx", "mesh-1", Instant.now(), null);
    }

    private static SshLicense licenseSample() {
        return new SshLicense("lic-1", "bob@brandx", SshLicense.SCOPE_DEVICE, "dev-1", null,
                "SHA256:abc", SshLicense.STATE_ACTIVE, "root", Instant.now(), null, null,
                "brandx", SshLicense.PROP_PENDING, 1L);
    }

    private static final String REGISTER_BODY = "{"
            + "\"machineKeyFp\":\"fp-aaa\",\"hostname\":\"brandx-node-1\","
            + "\"imageType\":\"mesh-extension\",\"ownerType\":\"ADMIN\","
            + "\"physicalOwner\":\"alice@brandx\",\"domain\":\"brandx\",\"meshId\":\"mesh-1\"}";

    private static final String GRANT_BODY =
            "{\"operator\":\"bob@brandx\",\"keyFingerprints\":[\"SHA256:abc\"]}";

    // ── SUPERADMIN write ALLOW ──────────────────────────────────────────────────

    @Test
    void register_asSuperadmin_isAllowed() {
        when(devices.register(any())).thenReturn(Mono.just(deviceSample()));
        asSuperadmin().post().uri("/bff/admin/device-licenses/register")
                .contentType(MediaType.APPLICATION_JSON).bodyValue(REGISTER_BODY)
                .exchange().expectStatus().isOk()
                .expectBody().jsonPath("$.id").isEqualTo("dev-1");
        verify(devices).register(any());
    }

    @Test
    void grantDevice_asSuperadmin_isAllowed_pinningKey() {
        when(licenses.grantDevice(eq("bob@brandx"), eq("dev-1"), anyList(), anyString()))
                .thenReturn(Mono.just(licenseSample()));
        asSuperadmin().post().uri("/bff/admin/device-licenses/dev-1/grant")
                .contentType(MediaType.APPLICATION_JSON).bodyValue(GRANT_BODY)
                .exchange().expectStatus().isOk()
                .expectBody().jsonPath("$.keyFingerprints").isEqualTo("SHA256:abc");
        verify(licenses).grantDevice(eq("bob@brandx"), eq("dev-1"),
                eq(List.of("SHA256:abc")), anyString());
    }

    @Test
    void grantDomain_asSuperadmin_isAllowed() {
        when(licenses.grantDomain(eq("bob@brandx"), eq("brandx"), anyList(), anyString()))
                .thenReturn(Mono.just(licenseSample()));
        asSuperadmin().post().uri("/bff/admin/device-licenses/domains/brandx/grant")
                .contentType(MediaType.APPLICATION_JSON).bodyValue(GRANT_BODY)
                .exchange().expectStatus().isOk();
        verify(licenses).grantDomain(eq("bob@brandx"), eq("brandx"), anyList(), anyString());
    }

    @Test
    void revoke_asSuperadmin_isAllowed() {
        when(licenses.revoke(eq("lic-1"), anyString(), any(PrincipalDomain.class))).thenReturn(Mono.just(1L));
        asSuperadmin().delete().uri("/bff/admin/device-licenses/licenses/lic-1")
                .exchange().expectStatus().isOk()
                .expectBody().jsonPath("$.revoked").isEqualTo(1);
        verify(licenses).revoke(eq("lic-1"), anyString(), any(PrincipalDomain.class));
    }

    @Test
    void deregister_asSuperadmin_isAllowed() {
        when(devices.deregister(eq("dev-1"), any(PrincipalDomain.class))).thenReturn(Mono.just(1L));
        asSuperadmin().delete().uri("/bff/admin/device-licenses/dev-1")
                .exchange().expectStatus().isOk()
                .expectBody().jsonPath("$.deregistered").isEqualTo(1);
        verify(devices).deregister(eq("dev-1"), any(PrincipalDomain.class));
    }

    @Test
    void export_perMesh_asSuperadmin_isAllowed() {
        ExportModels.ExportBody body = new ExportModels.ExportBody("mesh-1", 3L, List.of());
        when(export.exportMesh(eq("mesh-1"))).thenReturn(Mono.just(
                new ExportModels.SignedExport(body, "hash", "sig", "pub", true)));
        asSuperadmin().get().uri("/bff/admin/device-licenses/export?mesh=mesh-1")
                .exchange().expectStatus().isOk()
                .expectBody()
                .jsonPath("$.signed").isEqualTo(true)
                .jsonPath("$.body.meshId").isEqualTo("mesh-1");
        verify(export).exportMesh("mesh-1");
        // the per-mesh route NEVER triggers the per-node path.
        verify(export, never()).exportNode(anyString());
    }

    @Test
    void export_perNode_asSuperadmin_routesToExportNode_notMesh() {
        // CONFIDENTIALITY HARDENING: ?node=<fp> routes to the per-node export (Layer-B).
        ExportModels.ExportBody body = new ExportModels.ExportBody("mesh-1", 5L, List.of());
        when(export.exportNode(eq("fp-aaa"))).thenReturn(Mono.just(
                new ExportModels.SignedExport(body, "hash", "sig", "pub", true)));
        asSuperadmin().get().uri("/bff/admin/device-licenses/export?node=fp-aaa")
                .exchange().expectStatus().isOk()
                .expectBody()
                .jsonPath("$.signed").isEqualTo(true)
                .jsonPath("$.body.meshId").isEqualTo("mesh-1");
        verify(export).exportNode("fp-aaa");
        // the per-node route NEVER triggers the per-mesh path (no whole-mesh over-share).
        verify(export, never()).exportMesh(anyString());
    }

    @Test
    void export_nodeTakesPrecedenceOverMesh_whenBothGiven() {
        when(export.exportNode(eq("fp-aaa"))).thenReturn(Mono.just(
                new ExportModels.SignedExport(
                        new ExportModels.ExportBody("mesh-1", 1L, List.of()), "h", "s", "p", true)));
        asSuperadmin().get().uri("/bff/admin/device-licenses/export?node=fp-aaa&mesh=mesh-1")
                .exchange().expectStatus().isOk();
        verify(export).exportNode("fp-aaa");
        verify(export, never()).exportMesh(anyString());
    }

    @Test
    void export_withNeitherNodeNorMesh_isBadRequest_andNeverCallsService() {
        asSuperadmin().get().uri("/bff/admin/device-licenses/export")
                .exchange().expectStatus().isBadRequest();
        verify(export, never()).exportNode(anyString());
        verify(export, never()).exportMesh(anyString());
    }

    // ── ADMIN read ALLOW (own-domain wall is the service scope branch) ──────────

    @Test
    void list_asAdmin_isAllowed() {
        when(devices.list(any(PrincipalDomain.class))).thenReturn(Flux.just(deviceSample()));
        when(licenses.list(any(PrincipalDomain.class))).thenReturn(Flux.just(licenseSample()));
        asAdmin().get().uri("/bff/admin/device-licenses")
                .exchange().expectStatus().isOk()
                .expectBody()
                .jsonPath("$.devices[0].id").isEqualTo("dev-1")
                .jsonPath("$.licenses[0].id").isEqualTo("lic-1");
    }

    @Test
    void list_asSuperadmin_isAllowed() {
        when(devices.list(any(PrincipalDomain.class))).thenReturn(Flux.just(deviceSample()));
        when(licenses.list(any(PrincipalDomain.class))).thenReturn(Flux.empty());
        asSuperadmin().get().uri("/bff/admin/device-licenses")
                .exchange().expectStatus().isOk();
    }

    // ── PENDING pick-list (headscale enrolled LEFT-JOIN registry; READ-ONLY) ─────

    @Test
    void pending_asSuperadmin_isAllowed_returnsNodes() {
        when(pending.pending(any(PrincipalDomain.class))).thenReturn(Flux.just(
                new PendingNode("opaque-fp-1", "node-1", "brandx-user", "tag:mesh_1", false, null, null)));
        asSuperadmin().get().uri("/bff/admin/device-licenses/pending")
                .exchange().expectStatus().isOk()
                .expectBody()
                .jsonPath("$.nodes[0].machineKeyFp").isEqualTo("opaque-fp-1")
                .jsonPath("$.nodes[0].registered").isEqualTo(false);
        verify(pending).pending(any(PrincipalDomain.class));
    }

    @Test
    void pending_asAdmin_isAllowed_atCoarseGate() {
        // The own-domain wall is the DevicePendingService scope branch (mirrors the list view);
        // at the coarse gate an ADMIN passes.
        when(pending.pending(any(PrincipalDomain.class))).thenReturn(Flux.empty());
        asAdmin().get().uri("/bff/admin/device-licenses/pending")
                .exchange().expectStatus().isOk();
    }

    @Test
    void pending_asMod_isForbidden() {
        asMod().get().uri("/bff/admin/device-licenses/pending").exchange().expectStatus().isForbidden();
    }

    @Test
    void pending_asUser_isForbidden() {
        asUser().get().uri("/bff/admin/device-licenses/pending").exchange().expectStatus().isForbidden();
    }

    // ── ADMIN write DENY (403) + never reaches the service ──────────────────────

    @Test
    void register_asAdmin_isForbidden_andNeverWrites() {
        asAdmin().post().uri("/bff/admin/device-licenses/register")
                .contentType(MediaType.APPLICATION_JSON).bodyValue(REGISTER_BODY)
                .exchange().expectStatus().isForbidden();
        verify(devices, never()).register(any());
    }

    @Test
    void grantDevice_asAdmin_isForbidden_andNeverWrites() {
        asAdmin().post().uri("/bff/admin/device-licenses/dev-1/grant")
                .contentType(MediaType.APPLICATION_JSON).bodyValue(GRANT_BODY)
                .exchange().expectStatus().isForbidden();
        verify(licenses, never()).grantDevice(anyString(), anyString(), anyList(), anyString());
    }

    @Test
    void grantDomain_asAdmin_isForbidden_andNeverWrites() {
        asAdmin().post().uri("/bff/admin/device-licenses/domains/brandx/grant")
                .contentType(MediaType.APPLICATION_JSON).bodyValue(GRANT_BODY)
                .exchange().expectStatus().isForbidden();
        verify(licenses, never()).grantDomain(anyString(), anyString(), anyList(), anyString());
    }

    @Test
    void revoke_asAdmin_isForbidden_andNeverWrites() {
        asAdmin().delete().uri("/bff/admin/device-licenses/licenses/lic-1")
                .exchange().expectStatus().isForbidden();
        verify(licenses, never()).revoke(anyString(), anyString(), any(PrincipalDomain.class));
    }

    @Test
    void deregister_asAdmin_isForbidden_andNeverWrites() {
        asAdmin().delete().uri("/bff/admin/device-licenses/dev-1")
                .exchange().expectStatus().isForbidden();
        verify(devices, never()).deregister(anyString(), any(PrincipalDomain.class));
    }

    @Test
    void export_perMesh_asAdmin_isForbidden() {
        asAdmin().get().uri("/bff/admin/device-licenses/export?mesh=mesh-1")
                .exchange().expectStatus().isForbidden();
        verify(export, never()).exportMesh(anyString());
    }

    @Test
    void export_perNode_asAdmin_isForbidden() {
        // the per-node export is the SAME SUPERADMIN | internal-mTLS gate — an ADMIN JWT is
        // 403 and the service is never reached.
        asAdmin().get().uri("/bff/admin/device-licenses/export?node=fp-aaa")
                .exchange().expectStatus().isForbidden();
        verify(export, never()).exportNode(anyString());
    }

    // ── MOD / USER DENY (403) on read AND write ─────────────────────────────────

    @Test
    void list_asMod_isForbidden() {
        asMod().get().uri("/bff/admin/device-licenses").exchange().expectStatus().isForbidden();
    }

    @Test
    void list_asUser_isForbidden() {
        asUser().get().uri("/bff/admin/device-licenses").exchange().expectStatus().isForbidden();
    }

    @Test
    void register_asMod_isForbidden_andNeverWrites() {
        asMod().post().uri("/bff/admin/device-licenses/register")
                .contentType(MediaType.APPLICATION_JSON).bodyValue(REGISTER_BODY)
                .exchange().expectStatus().isForbidden();
        verify(devices, never()).register(any());
    }

    @Test
    void register_asUser_isForbidden_andNeverWrites() {
        asUser().post().uri("/bff/admin/device-licenses/register")
                .contentType(MediaType.APPLICATION_JSON).bodyValue(REGISTER_BODY)
                .exchange().expectStatus().isForbidden();
        verify(devices, never()).register(any());
    }

    // ── Validation: grant with NO pinned key is a 400 (FIX-PINKEY guard) ────────

    @Test
    void grantDevice_emptyKeyFingerprints_isBadRequest_andNeverWrites() {
        asSuperadmin().post().uri("/bff/admin/device-licenses/dev-1/grant")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"operator\":\"bob@brandx\",\"keyFingerprints\":[]}")
                .exchange().expectStatus().isBadRequest();
        verify(licenses, never()).grantDevice(anyString(), anyString(), anyList(), anyString());
    }

    // ── POST-VERIFY CORRECTION: service IllegalArgumentException maps to 422 ─────

    @Test
    void grantDevice_onSuperadminOwnedDevice_is422_fromServiceGuard() {
        // (a) The service rejects a SUPERADMIN-owned device target; the controller
        // onErrorResume maps the IllegalArgumentException to a clean 422 {error}.
        when(licenses.grantDevice(eq("bob@brandx"), eq("dev-1"), anyList(), anyString()))
                .thenReturn(Mono.error(new IllegalArgumentException(
                        "cannot grant an SSH license on a SUPERADMIN-owned device — "
                        + "superadmin reach is mesh-membership, not a license")));
        asSuperadmin().post().uri("/bff/admin/device-licenses/dev-1/grant")
                .contentType(MediaType.APPLICATION_JSON).bodyValue(GRANT_BODY)
                .exchange().expectStatus().isEqualTo(org.springframework.http.HttpStatus.UNPROCESSABLE_ENTITY)
                .expectBody().jsonPath("$.error").value(
                        org.hamcrest.Matchers.containsString("SUPERADMIN-owned"));
    }

    @Test
    void grantDomain_onUnknownOrDefaultDomain_is422_fromServiceGuard() {
        // (d) The service rejects a 'default'/unknown DOMAIN target [FIX-NODEFAULT]; the
        // controller maps it to a 422 {error} (added onErrorResume on the grantDomain path).
        when(licenses.grantDomain(eq("bob@brandx"), eq("default"), anyList(), anyString()))
                .thenReturn(Mono.error(new IllegalArgumentException(
                        "DOMAIN-license target must be a real residency domain, not 'default'/blank")));
        asSuperadmin().post().uri("/bff/admin/device-licenses/domains/default/grant")
                .contentType(MediaType.APPLICATION_JSON).bodyValue(GRANT_BODY)
                .exchange().expectStatus().isEqualTo(org.springframework.http.HttpStatus.UNPROCESSABLE_ENTITY)
                .expectBody().jsonPath("$.error").value(
                        org.hamcrest.Matchers.containsString("default"));
    }

    @Test
    void register_invalidImageType_isBadRequest_andNeverWrites() {
        asSuperadmin().post().uri("/bff/admin/device-licenses/register")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"machineKeyFp\":\"fp\",\"hostname\":\"h\",\"imageType\":\"bogus\","
                        + "\"ownerType\":\"ADMIN\",\"physicalOwner\":\"a\",\"domain\":\"brandx\","
                        + "\"meshId\":\"mesh-1\"}")
                .exchange().expectStatus().isBadRequest();
        verify(devices, never()).register(any());
    }
}
