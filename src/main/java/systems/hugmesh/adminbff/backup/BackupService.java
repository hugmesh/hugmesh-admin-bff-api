package systems.hugmesh.adminbff.backup;

import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import systems.hugmesh.commons.security.PrincipalDomain;
import systems.hugmesh.commons.web.ApiException;

import java.util.Arrays;
import java.util.List;
import java.util.UUID;

/**
 * Backup / restore application service (reactive). Owns the rules the controller
 * must not duplicate:
 * <ul>
 *   <li>scope normalisation/validation (closed {@link BackupScope} vocabulary);</li>
 *   <li>USB target/source existence (a {@code USB} target requires a present,
 *       writable {@code usbDeviceId} — else 404/422 via {@link ApiException});</li>
 *   <li>encryption verifier creation at backup time + password verification at
 *       restore time (never reveals the key — wrong password is 403);</li>
 *   <li>handing the validated job to the {@link BackupOrchestrator} which
 *       templates the k8s Job and streams progress.</li>
 * </ul>
 */
@Service
public class BackupService {

    private final BackupRepository repo;
    private final BackupCrypto crypto;
    private final BackupOrchestrator orchestrator;
    private final UsbDeviceProvider usb;

    public BackupService(BackupRepository repo, BackupCrypto crypto,
                         BackupOrchestrator orchestrator, UsbDeviceProvider usb) {
        this.repo = repo;
        this.crypto = crypto;
        this.orchestrator = orchestrator;
        this.usb = usb;
    }

    /** Backup history VISIBLE to the caller's tenant (SUPERADMIN sees all brands). */
    public Flux<BackupRecord> history(PrincipalDomain scope) {
        return repo.list(scope);
    }

    public Mono<List<UsbDevice>> usbDevices() {
        return usb.list();
    }

    public Flux<JobEvent> events(String jobId) {
        return orchestrator.events(jobId);
    }

    /**
     * Start a backup. Validates scope + target (+ USB presence/writability), creates
     * the durable QUEUED row (with a PBKDF2 verifier when encrypted — never the
     * password), then launches the worker. Returns the new backup id.
     */
    public Mono<String> startBackup(String requestedBy, List<String> scope, String target,
                                    String usbDeviceId, boolean encrypt, String password,
                                    PrincipalDomain tenantScope) {
        final String normalisedScope;
        try {
            normalisedScope = BackupScope.normalise(scope);
        } catch (IllegalArgumentException e) {
            return Mono.error(ApiException.badRequest(e.getMessage()));
        }
        final String normalisedTarget = normaliseTarget(target);
        if (encrypt && (password == null || password.isBlank())) {
            return Mono.error(ApiException.badRequest("password is required when encrypt is true"));
        }

        final String salt = encrypt ? crypto.newSalt() : null;
        final String verifier = encrypt ? crypto.verifier(password, salt) : null;
        final List<String> scopes = Arrays.asList(normalisedScope.split(","));

        // For a USB target the device must be present + writable BEFORE we persist a
        // job (so a missing stick is a clean 404 with no orphan row).
        Mono<Void> targetCheck = "USB".equals(normalisedTarget)
                ? requireWritableUsb(usbDeviceId).then()
                : Mono.empty();

        return targetCheck.then(
                repo.insert(requestedBy, normalisedScope, normalisedTarget, encrypt, salt, verifier, tenantScope)
                        .flatMap(rec -> orchestrator.launchBackup(rec, scopes, encrypt ? password : null)
                                .thenReturn(rec.id())));
    }

    /**
     * Start a restore. Resolves the source ({@code backupId} from history). If the
     * source is encrypted the supplied {@code password} is verified against the
     * stored PBKDF2 verifier — a mismatch is a 403 and the key is never derived/
     * revealed. Returns a fresh restore job id whose progress streams on
     * {@link #events}.
     */
    public Mono<String> startRestore(String backupId, List<String> scope, String password,
                                     PrincipalDomain tenantScope) {
        if (backupId == null || backupId.isBlank()) {
            return Mono.error(ApiException.badRequest("backupId is required"));
        }
        return repo.find(backupId, tenantScope)
                .switchIfEmpty(Mono.error(new ApiException(HttpStatus.NOT_FOUND, "backup '" + backupId + "' not found")))
                // Verify the password (when encrypted) then launch the restore worker.
                .flatMap(src -> processRestoreSource(src, scope, password));
    }

    /** Verify decryption password (when encrypted), resolve scopes, then launch the restore worker. */
    private Mono<String> processRestoreSource(BackupRecord src, List<String> scope, String password) {
        if (src.encrypted()) {
            if (password == null || password.isBlank()) {
                return Mono.error(ApiException.badRequest("password is required to restore an encrypted backup"));
            }
            if (!crypto.matches(password, src.verifierSalt(), src.verifier())) {
                // Never reveal the key; never say WHICH part was wrong.
                return Mono.error(ApiException.forbidden("incorrect decryption password"));
            }
        }
        // Restore the source's scope unless the caller narrows it (still validated
        // against the closed vocabulary).
        List<String> scopes;
        try {
            scopes = (scope == null || scope.isEmpty())
                    ? Arrays.asList(src.scope().split(","))
                    : Arrays.asList(BackupScope.normalise(scope).split(","));
        } catch (IllegalArgumentException e) {
            return Mono.error(ApiException.badRequest(e.getMessage()));
        }
        String restoreJobId = UUID.randomUUID().toString();
        return orchestrator.launchRestore(restoreJobId, src, scopes,
                src.encrypted() ? password : null).thenReturn(restoreJobId);
    }

    private Mono<UsbDevice> requireWritableUsb(String usbDeviceId) {
        if (usbDeviceId == null || usbDeviceId.isBlank()) {
            return Mono.error(ApiException.badRequest("usbDeviceId is required when target is USB"));
        }
        return usb.find(usbDeviceId)
                .switchIfEmpty(Mono.error(new ApiException(HttpStatus.NOT_FOUND,
                        "USB device '" + usbDeviceId + "' not found / not connected")))
                .flatMap(d -> d.writable()
                        ? Mono.just(d)
                        : Mono.error(new ApiException(HttpStatus.UNPROCESSABLE_CONTENT,
                                "USB device '" + usbDeviceId + "' is read-only")));
    }

    private static String normaliseTarget(String target) {
        String t = target == null ? "" : target.trim().toUpperCase();
        if (!"CLUSTER".equals(t) && !"USB".equals(t)) {
            throw ApiException.badRequest("target must be CLUSTER or USB");
        }
        return t;
    }
}
