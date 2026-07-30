package systems.hugmesh.adminbff.backup;
import org.junit.jupiter.api.BeforeEach;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.boot.webflux.test.autoconfigure.WebFluxTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.reactive.server.WebTestClient;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import systems.hugmesh.adminbff.config.SecurityConfig;
import systems.hugmesh.commons.web.ApiException;
import systems.hugmesh.adminbff.web.ApiExceptionHandler;
import systems.hugmesh.adminbff.web.ValidationExceptionHandler;

import java.util.List;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.mockJwt;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.springSecurity;

/**
 * Web-layer contract for the Backup &amp; Recovery endpoints: ADMIN gating
 * (@PreAuthorize via SecurityConfig's @EnableReactiveMethodSecurity), jakarta
 * bean-validation 400s ({error,fields} via ValidationExceptionHandler), and the
 * application-error mapping (wrong password 403, USB not found 404 via
 * ApiExceptionHandler). The service is mocked; the deeper service/crypto behaviour
 * is covered in BackupServiceTest / BackupCryptoTest.
 */
@WebFluxTest(controllers = BackupController.class)
@Import({SecurityConfig.class, systems.hugmesh.commons.security.DomainRegistry.class, ValidationExceptionHandler.class, ApiExceptionHandler.class})
class BackupControllerTest {

    @Autowired ApplicationContext context;

    WebTestClient web;

    @BeforeEach
    void setUpWebTestClient() {
        web = WebTestClient.bindToApplicationContext(context).apply(springSecurity()).build();
    }

    @MockitoBean BackupService service;
    @MockitoBean ReactiveJwtDecoder jwtDecoder;

    private WebTestClient asAdmin() {
        return web.mutateWith(mockJwt().authorities(
                new SimpleGrantedAuthority("ROLE_USER"), new SimpleGrantedAuthority("ROLE_ADMIN")));
    }

    private WebTestClient asUser() {
        return web.mutateWith(mockJwt().authorities(new SimpleGrantedAuthority("ROLE_USER")));
    }

    // ── happy path ──────────────────────────────────────────────────────
    @Test
    void startBackup_valid_returnsIdAndStatus() {
        when(service.startBackup(anyString(), anyList(), eq("CLUSTER"), any(), eq(false), any(), any()))
                .thenReturn(Mono.just("backup-123"));
        asAdmin().post().uri("/bff/admin/backups").contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"scope\":[\"etcd\",\"postgres\"],\"target\":\"CLUSTER\",\"encrypt\":false}")
                .exchange().expectStatus().isOk()
                .expectBody()
                .jsonPath("$.id").isEqualTo("backup-123")
                .jsonPath("$.status").isEqualTo("QUEUED");
    }

    @Test
    void history_returnsBackupsList() {
        BackupRecord rec = new BackupRecord("id1", java.time.Instant.now(), "admin@x",
                "etcd", "CLUSTER", false, "COMPLETED", 4096L, null, "cluster://id1", null, null);
        when(service.history(any())).thenReturn(Flux.just(rec));
        asAdmin().get().uri("/bff/admin/backups").exchange().expectStatus().isOk()
                .expectBody()
                .jsonPath("$.backups[0].id").isEqualTo("id1")
                .jsonPath("$.backups[0].status").isEqualTo("COMPLETED")
                // the verifier columns must never be serialised to the UI.
                .jsonPath("$.backups[0].verifier").doesNotExist()
                .jsonPath("$.backups[0].verifierSalt").doesNotExist();
    }

    @Test
    void usbDevices_returnsDeviceList() {
        when(service.usbDevices()).thenReturn(Mono.just(List.of(
                new UsbDevice("usb-1", "BACKUP", "/mnt/usb", 1L, 1L, true, List.of()))));
        asAdmin().get().uri("/bff/admin/usb-devices").exchange().expectStatus().isOk()
                .expectBody().jsonPath("$.devices[0].id").isEqualTo("usb-1");
    }

    // ── validation (400 {error,fields}) ─────────────────────────────────
    @Test
    void startBackup_emptyScope_400_andNoServiceCall() {
        asAdmin().post().uri("/bff/admin/backups").contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"scope\":[],\"target\":\"CLUSTER\",\"encrypt\":false}")
                .exchange().expectStatus().isBadRequest()
                .expectBody()
                .jsonPath("$.error").isEqualTo("validation failed")
                .jsonPath("$.fields.scope").exists();
        verify(service, never()).startBackup(anyString(), anyList(), anyString(), any(), anyBoolean(), any(), any());
    }

    @Test
    void startBackup_badTarget_400() {
        asAdmin().post().uri("/bff/admin/backups").contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"scope\":[\"etcd\"],\"target\":\"FLOPPY\",\"encrypt\":false}")
                .exchange().expectStatus().isBadRequest()
                .expectBody().jsonPath("$.fields.target").exists();
    }

    @Test
    void startRestore_malformedBackupId_400() {
        asAdmin().post().uri("/bff/admin/restores").contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"backupId\":\"not-a-uuid\"}")
                .exchange().expectStatus().isBadRequest()
                .expectBody().jsonPath("$.fields.backupId").exists();
    }

    // ── application errors mapped via ApiExceptionHandler ───────────────
    @Test
    void startRestore_wrongPassword_403() {
        when(service.startRestore(anyString(), any(), eq("wrong-but-long-enough"), any()))
                .thenReturn(Mono.error(ApiException.forbidden("incorrect decryption password")));
        asAdmin().post().uri("/bff/admin/restores").contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"backupId\":\"11111111-2222-3333-4444-555555555555\",\"password\":\"wrong-but-long-enough\"}")
                .exchange().expectStatus().isForbidden()
                .expectBody().jsonPath("$.error").isEqualTo("incorrect decryption password");
    }

    @Test
    void startBackup_usbNotFound_404() {
        when(service.startBackup(anyString(), anyList(), eq("USB"), eq("ghost"), eq(false), any(), any()))
                .thenReturn(Mono.error(new ApiException(HttpStatus.NOT_FOUND,
                        "USB device 'ghost' not found / not connected")));
        asAdmin().post().uri("/bff/admin/backups").contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"scope\":[\"config\"],\"target\":\"USB\",\"usbDeviceId\":\"ghost\",\"encrypt\":false}")
                .exchange().expectStatus().isNotFound()
                .expectBody().jsonPath("$.error").value(org.hamcrest.Matchers.containsString("not found"));
    }

    // ── admin gating (403 for non-admin) ────────────────────────────────
    @Test
    void startBackup_nonAdmin_403() {
        asUser().post().uri("/bff/admin/backups").contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"scope\":[\"etcd\"],\"target\":\"CLUSTER\",\"encrypt\":false}")
                .exchange().expectStatus().isForbidden();
        verify(service, never()).startBackup(anyString(), anyList(), anyString(), any(), anyBoolean(), any(), any());
    }

    @Test
    void history_nonAdmin_403() {
        asUser().get().uri("/bff/admin/backups").exchange().expectStatus().isForbidden();
    }

    @Test
    void usbDevices_unauthenticated_401() {
        web.get().uri("/bff/admin/usb-devices").exchange().expectStatus().isUnauthorized();
    }

    // ── SSE stream ──────────────────────────────────────────────────────
    @Test
    void events_streamsServerSentEvents() {
        when(service.events("backup-123")).thenReturn(Flux.just(
                JobEvent.progress("backup-123", "etcd", 50, "processing etcd"),
                JobEvent.complete("backup-123", "done")));
        asAdmin().get().uri("/bff/admin/backups/backup-123/events")
                .accept(MediaType.TEXT_EVENT_STREAM)
                .exchange().expectStatus().isOk()
                .expectHeader().contentTypeCompatibleWith(MediaType.TEXT_EVENT_STREAM);
    }
}
