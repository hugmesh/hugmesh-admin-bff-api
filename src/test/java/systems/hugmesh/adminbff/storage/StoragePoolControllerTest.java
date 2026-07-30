package systems.hugmesh.adminbff.storage;
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
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.mockJwt;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.springSecurity;

/**
 * The NODE STORAGE controller role + error-mapping matrix on
 * {@code /bff/admin/device-storage-pools}. Mirrors {@code DeviceLicenseControllerTest}
 * ({@code @WebFluxTest} + the real {@link SecurityConfig}), with the DELIBERATE DIVERGENCE
 * that storage is ADMIN-CAPABLE: an ADMIN may reach AND mutate the path (the OWNERSHIP
 * ALLOW/DENY matrix is the downstream service wall, exercised in
 * {@link NodeStorageServiceTest}). Proves:
 * <ul>
 *   <li>ADMIN + SUPERADMIN read/write ALLOW at the path gate;</li>
 *   <li>MOD / USER DENY (403) on read AND write, never reaching the service;</li>
 *   <li>a service DENY ({@link StorageAccessDeniedException}) maps to 403;</li>
 *   <li>a service over-subscription / validation ({@link IllegalArgumentException}) maps
 *       to 422;</li>
 *   <li>a malformed body (no diskSerial / non-positive bytes) is a 400, never a write.</li>
 * </ul>
 */
@WebFluxTest(controllers = StoragePoolController.class)
@Import({SecurityConfig.class, DomainRegistry.class, ValidationExceptionHandler.class, ApiExceptionHandler.class})
class StoragePoolControllerTest {

    @Autowired ApplicationContext context;

    WebTestClient web;

    @BeforeEach
    void setUpWebTestClient() {
        web = WebTestClient.bindToApplicationContext(context).apply(springSecurity()).build();
    }

    @MockitoBean NodeStorageService storage;
    @MockitoBean NodeStorageExportService export;
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

    private static StoragePool poolSample() {
        return new StoragePool("pool-1", "dev-1", "ser-1", "/var/hugmesh/storage/pool-1",
                10_000L, false, "ext4", StoragePool.STATE_ACTIVE, "brandx",
                StoragePool.PROP_PENDING, 1L, "alice@brandx", Instant.now(), null, null);
    }

    private static ServiceAssignment assignmentSample() {
        return new ServiceAssignment("a-1", "pool-1", "owncast", "owncast-data", 4_000L,
                ServiceAssignment.STATE_ACTIVE, "alice@brandx", Instant.now(), null, null,
                "brandx", ServiceAssignment.PROP_PENDING, 1L);
    }

    private static final String ATTACH_BODY =
            "{\"diskSerial\":\"ser-1\",\"poolPath\":\"/var/hugmesh/storage/pool-1\","
            + "\"reservedBytes\":10000,\"exclusive\":false,\"filesystem\":\"ext4\"}";

    private static final String ASSIGN_BODY =
            "{\"serviceName\":\"owncast\",\"pvcName\":\"owncast-data\",\"requestedBytes\":4000}";

    // ── ADMIN + SUPERADMIN read/write ALLOW at the path gate ────────────────────

    @Test
    void list_asAdmin_isAllowed() {
        when(storage.listPools(any(PrincipalDomain.class))).thenReturn(Flux.just(poolSample()));
        when(storage.listAssignments(any(PrincipalDomain.class))).thenReturn(Flux.just(assignmentSample()));
        asAdmin().get().uri("/bff/admin/device-storage-pools")
                .exchange().expectStatus().isOk()
                .expectBody()
                .jsonPath("$.pools[0].id").isEqualTo("pool-1")
                .jsonPath("$.assignments[0].id").isEqualTo("a-1");
    }

    @Test
    void list_asSuperadmin_isAllowed() {
        when(storage.listPools(any(PrincipalDomain.class))).thenReturn(Flux.just(poolSample()));
        when(storage.listAssignments(any(PrincipalDomain.class))).thenReturn(Flux.empty());
        asSuperadmin().get().uri("/bff/admin/device-storage-pools")
                .exchange().expectStatus().isOk();
    }

    @Test
    void attach_asAdmin_isAllowed() {
        when(storage.attachPool(eq("dev-1"), eq("ser-1"), anyString(), eq(10_000L), eq(false),
                anyString(), any(PrincipalDomain.class), anyString()))
                .thenReturn(Mono.just(poolSample()));
        asAdmin().post().uri("/bff/admin/device-storage-pools/dev-1/pools")
                .contentType(MediaType.APPLICATION_JSON).bodyValue(ATTACH_BODY)
                .exchange().expectStatus().isOk()
                .expectBody().jsonPath("$.id").isEqualTo("pool-1");
        verify(storage).attachPool(eq("dev-1"), eq("ser-1"), anyString(), eq(10_000L), eq(false),
                anyString(), any(PrincipalDomain.class), anyString());
    }

    @Test
    void assign_asSuperadmin_isAllowed() {
        when(storage.assignService(eq("pool-1"), eq("owncast"), eq("owncast-data"), eq(4_000L),
                any(PrincipalDomain.class), anyString()))
                .thenReturn(Mono.just(assignmentSample()));
        asSuperadmin().post().uri("/bff/admin/device-storage-pools/pools/pool-1/assignments")
                .contentType(MediaType.APPLICATION_JSON).bodyValue(ASSIGN_BODY)
                .exchange().expectStatus().isOk()
                .expectBody().jsonPath("$.serviceName").isEqualTo("owncast");
    }

    @Test
    void detach_asAdmin_isAllowed() {
        when(storage.detachPool(eq("pool-1"), any(PrincipalDomain.class), anyString()))
                .thenReturn(Mono.just(1L));
        asAdmin().delete().uri("/bff/admin/device-storage-pools/pools/pool-1")
                .exchange().expectStatus().isOk()
                .expectBody().jsonPath("$.detached").isEqualTo(1);
    }

    @Test
    void revoke_asAdmin_isAllowed() {
        when(storage.revokeAssignment(eq("a-1"), any(PrincipalDomain.class), anyString()))
                .thenReturn(Mono.just(1L));
        asAdmin().delete().uri("/bff/admin/device-storage-pools/assignments/a-1")
                .exchange().expectStatus().isOk()
                .expectBody().jsonPath("$.revoked").isEqualTo(1);
    }

    // ── MOD / USER DENY (403) on read AND write ─────────────────────────────────

    @Test
    void list_asMod_isForbidden() {
        asMod().get().uri("/bff/admin/device-storage-pools").exchange().expectStatus().isForbidden();
    }

    @Test
    void list_asUser_isForbidden() {
        asUser().get().uri("/bff/admin/device-storage-pools").exchange().expectStatus().isForbidden();
    }

    @Test
    void attach_asMod_isForbidden_andNeverWrites() {
        asMod().post().uri("/bff/admin/device-storage-pools/dev-1/pools")
                .contentType(MediaType.APPLICATION_JSON).bodyValue(ATTACH_BODY)
                .exchange().expectStatus().isForbidden();
        verify(storage, never()).attachPool(anyString(), anyString(), anyString(), anyLong(),
                org.mockito.ArgumentMatchers.anyBoolean(), any(), any(PrincipalDomain.class), anyString());
    }

    @Test
    void assign_asUser_isForbidden_andNeverWrites() {
        asUser().post().uri("/bff/admin/device-storage-pools/pools/pool-1/assignments")
                .contentType(MediaType.APPLICATION_JSON).bodyValue(ASSIGN_BODY)
                .exchange().expectStatus().isForbidden();
        verify(storage, never()).assignService(anyString(), anyString(), anyString(), anyLong(),
                any(PrincipalDomain.class), anyString());
    }

    // ── service DENY (StorageAccessDeniedException) -> 403 ──────────────────────

    @Test
    void attach_onSuperadminOwnedNode_byAdmin_is403_fromServiceGate() {
        // The ownership matrix DENY surfaces from the service as a clean 403 {error}.
        when(storage.attachPool(eq("core"), anyString(), anyString(), anyLong(),
                org.mockito.ArgumentMatchers.anyBoolean(), any(), any(PrincipalDomain.class), anyString()))
                .thenReturn(Mono.error(new StorageAccessDeniedException(
                        "node core is SUPERADMIN-owned — only a SUPERADMIN may manage its storage")));
        asAdmin().post().uri("/bff/admin/device-storage-pools/core/pools")
                .contentType(MediaType.APPLICATION_JSON).bodyValue(ATTACH_BODY)
                .exchange().expectStatus().isForbidden()
                .expectBody().jsonPath("$.error").value(
                        org.hamcrest.Matchers.containsString("SUPERADMIN-owned"));
    }

    // ── service over-subscription (IllegalArgumentException) -> 422 ─────────────

    @Test
    void assign_overSubscription_is422_fromServiceGuard() {
        when(storage.assignService(eq("pool-1"), anyString(), anyString(), anyLong(),
                any(PrincipalDomain.class), anyString()))
                .thenReturn(Mono.error(new IllegalArgumentException(
                        "over-subscription: pool pool-1 reserved=10000 committed=7000 requested=5000")));
        asSuperadmin().post().uri("/bff/admin/device-storage-pools/pools/pool-1/assignments")
                .contentType(MediaType.APPLICATION_JSON).bodyValue(ASSIGN_BODY)
                .exchange().expectStatus().isEqualTo(org.springframework.http.HttpStatus.UNPROCESSABLE_ENTITY)
                .expectBody().jsonPath("$.error").value(
                        org.hamcrest.Matchers.containsString("over-subscription"));
    }

    // ── validation: malformed body is a 400, never a write ──────────────────────

    @Test
    void attach_missingDiskSerial_isBadRequest_andNeverWrites() {
        asAdmin().post().uri("/bff/admin/device-storage-pools/dev-1/pools")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"poolPath\":\"/p\",\"reservedBytes\":10000,\"exclusive\":false}")
                .exchange().expectStatus().isBadRequest();
        verify(storage, never()).attachPool(anyString(), anyString(), anyString(), anyLong(),
                org.mockito.ArgumentMatchers.anyBoolean(), any(), any(PrincipalDomain.class), anyString());
    }

    @Test
    void attach_nonPositiveReserved_isBadRequest_andNeverWrites() {
        asAdmin().post().uri("/bff/admin/device-storage-pools/dev-1/pools")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"diskSerial\":\"s\",\"poolPath\":\"/p\",\"reservedBytes\":0,\"exclusive\":false}")
                .exchange().expectStatus().isBadRequest();
        verify(storage, never()).attachPool(anyString(), anyString(), anyString(), anyLong(),
                org.mockito.ArgumentMatchers.anyBoolean(), any(), any(PrincipalDomain.class), anyString());
    }

    @Test
    void assign_missingPvc_isBadRequest_andNeverWrites() {
        asAdmin().post().uri("/bff/admin/device-storage-pools/pools/pool-1/assignments")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"serviceName\":\"owncast\",\"requestedBytes\":4000}")
                .exchange().expectStatus().isBadRequest();
        verify(storage, never()).assignService(anyString(), anyString(), anyString(), anyLong(),
                any(PrincipalDomain.class), anyString());
    }

    // ── Signed per-node export — SUPERADMIN | internal-mTLS ONLY ─────────────────

    @Test
    void export_asSuperadmin_isAllowed() {
        var body = new StorageExportModels.StorageExportBody("fp-aaa", 3L, java.util.List.of());
        when(export.exportNode(eq("fp-aaa"))).thenReturn(Mono.just(
                new StorageExportModels.SignedStorageExport(body, "hash", "sig", "pub", true)));
        asSuperadmin().get().uri("/bff/admin/device-storage-pools/export?node=fp-aaa")
                .exchange().expectStatus().isOk()
                .expectBody()
                .jsonPath("$.signed").isEqualTo(true)
                .jsonPath("$.body.nodeFp").isEqualTo("fp-aaa");
        verify(export).exportNode("fp-aaa");
    }

    @Test
    void export_asAdmin_isForbidden_andNeverReachesService() {
        // The export is the SAME SUPERADMIN | internal-mTLS gate as the device export — an
        // ADMIN JWT is 403 (a node never learns its pools via an ADMIN principal).
        asAdmin().get().uri("/bff/admin/device-storage-pools/export?node=fp-aaa")
                .exchange().expectStatus().isForbidden();
        verify(export, never()).exportNode(anyString());
    }

    @Test
    void export_asMod_isForbidden() {
        asMod().get().uri("/bff/admin/device-storage-pools/export?node=fp-aaa")
                .exchange().expectStatus().isForbidden();
        verify(export, never()).exportNode(anyString());
    }

    @Test
    void export_withNoNode_isBadRequest_andNeverReachesService() {
        asSuperadmin().get().uri("/bff/admin/device-storage-pools/export")
                .exchange().expectStatus().isBadRequest();
        verify(export, never()).exportNode(anyString());
    }
}
