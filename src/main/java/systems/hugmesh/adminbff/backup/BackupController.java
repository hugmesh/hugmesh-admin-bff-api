package systems.hugmesh.adminbff.backup;

import io.swagger.v3.oas.annotations.Operation;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import org.springframework.http.MediaType;
import org.springframework.http.codec.ServerSentEvent;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import systems.hugmesh.adminbff.web.dto.StartBackupRequest;
import systems.hugmesh.adminbff.web.dto.StartRestoreRequest;
import systems.hugmesh.commons.security.DomainRegistry;
import systems.hugmesh.commons.security.PrincipalDomain;

import java.util.Map;

/**
 * ADMIN-only cloud Backup &amp; Recovery endpoints (reactive WebFlux). Admin
 * gating is defence-in-depth identical to {@link systems.hugmesh.adminbff.AdminController}:
 * the gateway denies {@code /bff/admin/**} to non-admins, the resource-server
 * filter re-applies {@code hasRole('ADMIN')} on the path, AND
 * {@code @PreAuthorize("hasRole('ADMIN')")} re-checks at every method here.
 *
 * <ul>
 *   <li>{@code POST /bff/admin/backups} — start a backup → {backupId}.</li>
 *   <li>{@code GET  /bff/admin/backups} — backup history.</li>
 *   <li>{@code GET  /bff/admin/backups/{id}/events} — SSE progress (backup OR restore id).</li>
 *   <li>{@code GET  /bff/admin/usb-devices} — connected USB targets/sources (+ backups on them).</li>
 *   <li>{@code POST /bff/admin/restores} — start a restore → {restoreId}.</li>
 * </ul>
 *
 * <p>Validation: jakarta Bean Validation on the typed request bodies (@Valid); a
 * malformed body is a clean 400 {error,fields} via the existing reactive
 * {@code ValidationExceptionHandler}. Application-level failures (USB not found,
 * wrong decryption password, unknown scope) are {@code ApiException}s mapped to
 * the {@code {error}} body by {@code ApiExceptionHandler}.
 */
@RestController
@RequestMapping("/bff/admin")
@Validated
public class BackupController {

    private final BackupService service;
    private final DomainRegistry domainRegistry;

    public BackupController(BackupService service, DomainRegistry domainRegistry) {
        this.service = service;
        this.domainRegistry = domainRegistry;
    }

    /** The acting principal's tenant scope (brand-ADMIN constrained; SUPERADMIN unscoped). */
    private PrincipalDomain scope(Authentication auth) {
        return PrincipalDomain.of(auth, domainRegistry);
    }

    // ── Start a backup ──────────────────────────────────────────────────
    @PreAuthorize("hasRole('ADMIN')")
    @Operation(summary = "Start backup", operationId = "backupStartBackup")
    @PostMapping("/backups")
    public Mono<Map<String, Object>> startBackup(@Valid @RequestBody StartBackupRequest b, Authentication auth) {
        return service.startBackup(actor(auth), b.scope(), b.target(), b.usbDeviceId(), b.encrypt(),
                        b.password(), scope(auth))
                .map(id -> Map.of("id", id, "status", "QUEUED"));
    }

    // ── Backup history ──────────────────────────────────────────────────
    @PreAuthorize("hasRole('ADMIN')")
    @Operation(summary = "History", operationId = "backupHistory")
    @GetMapping("/backups")
    public Mono<Map<String, Object>> history(Authentication auth) {
        return service.history(scope(auth)).collectList().map(list -> Map.of("backups", list));
    }

    // ── SSE progress for a running backup OR restore ────────────────────
    @PreAuthorize("hasRole('ADMIN')")
    @Operation(summary = "Events", operationId = "backupEvents")
    @GetMapping(value = "/backups/{id}/events", produces = MediaType.TEXT_EVENT_STREAM_VALUE)
    public Flux<ServerSentEvent<JobEvent>> events(
            @PathVariable
            @NotBlank(message = "id is required")
            @Size(max = 100, message = "id is too long")
            String id) {
        return service.events(id)
                .map(ev -> ServerSentEvent.<JobEvent>builder(ev)
                        .event(ev.done() ? (ev.error() == null ? "complete" : "error") : "progress")
                        .build());
    }

    // ── Connected USB devices (targets / sources) ───────────────────────
    @PreAuthorize("hasRole('ADMIN')")
    @Operation(summary = "Usb devices", operationId = "backupUsbDevices")
    @GetMapping("/usb-devices")
    public Mono<Map<String, Object>> usbDevices() {
        return service.usbDevices().map(devices -> Map.of("devices", devices));
    }

    // ── Start a restore ─────────────────────────────────────────────────
    @PreAuthorize("hasRole('ADMIN')")
    @Operation(summary = "Start restore", operationId = "backupStartRestore")
    @PostMapping("/restores")
    public Mono<Map<String, Object>> startRestore(@Valid @RequestBody StartRestoreRequest b, Authentication auth) {
        return service.startRestore(b.backupId(), b.scope(), b.password(), scope(auth))
                .map(id -> Map.of("id", id, "status", "QUEUED"));
    }

    /** The acting admin's identity (JWT subject/name) for {@code requested_by}. */
    private static String actor(Authentication auth) {
        return auth == null ? "admin" : auth.getName();
    }
}
