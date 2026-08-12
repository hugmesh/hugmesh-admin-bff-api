package net.hugmesh.adminbff.cloudbackup;

import io.swagger.v3.oas.annotations.Operation;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import net.hugmesh.authcore.casdoor.MfaStepUpService;
import net.hugmesh.authcore.config.SessionCookieWebFilter;
import net.hugmesh.commons.security.DomainRegistry;
import net.hugmesh.commons.security.PrincipalDomain;
import net.hugmesh.commons.web.ApiException;
import net.hugmesh.adminbff.web.dto.BackupDestinationRequest;
import net.hugmesh.adminbff.web.dto.CreateBackupRequest;

import java.util.Map;

/**
 * The per-domain CLOUD-BACKUPS surface (ADMIN/SUPERADMIN) at {@code /bff/admin/cloud-backups}
 * — the SOURCE-OF-TRUTH catalog for the per-domain encrypted, versioned backups feature.
 * Mounted under a DISTINCT prefix from the legacy USB {@code BackupController}
 * ({@code /bff/admin/backups}) so the two coexist without route collision.
 *
 * <h3>Authorization</h3>
 * Mounted under {@code /bff/admin/**} (coarse gate {@code hasAnyRole('ADMIN','SUPERADMIN')});
 * each method carries {@code @PreAuthorize("hasAnyRole('ADMIN','SUPERADMIN')")}. MOD/USER ->
 * 403; unauthenticated -> 401. Every read/write is DOMAIN-scoped via {@link PrincipalDomain} (the
 * validated issuer): a scoped ADMIN sees/writes ONLY their own brand's rows; a SUPERADMIN is
 * unscoped (and may filter the list cross-domain). The {@code domain} + {@code createdBy} are
 * STAMPED server-side, never body fields.
 *
 * <ul>
 *   <li>{@code GET  /bff/admin/cloud-backups} — list (own domain; SUPERADMIN may
 *       {@code ?domain=} filter).</li>
 *   <li>{@code POST /bff/admin/cloud-backups} — create a per-domain (DOMAIN-scope) backup.</li>
 *   <li>{@code GET  /bff/admin/cloud-backups/{id}/versions} — version history.</li>
 *   <li>{@code GET  /bff/admin/cloud-backups/{id}/artifacts} — per-service artifact detail.</li>
 *   <li>{@code POST /bff/admin/cloud-backups/{id}/restore} — restore (PRIVILEGED: requires a
 *       satisfied STEP-UP, presented in the {@code X-Backup-StepUp} header).</li>
 *   <li>{@code GET  /bff/admin/cloud-backups/services} — the per-service backup menu.</li>
 *   <li>{@code GET/PUT /bff/admin/cloud-backups/destinations} — destination config.</li>
 * </ul>
 *
 * The TOTAL-CLOUD (scope=TOTAL) backup is reached ONLY via the SUPERADMIN-only
 * {@link BackupSuperadminController}, so a scoped admin can never request a total backup here.
 */
@RestController
@RequestMapping("/bff/admin/cloud-backups")
@Validated
public class BackupAdminController {

    private static final Logger log = LoggerFactory.getLogger(BackupAdminController.class);

    private final BackupService service;
    private final BackupStepUpGate stepUp;
    private final MfaStepUpService mfaStepUp;
    private final DomainRegistry domainRegistry;

    public BackupAdminController(BackupService service, BackupStepUpGate stepUp,
                                 MfaStepUpService mfaStepUp, DomainRegistry domainRegistry) {
        this.service = service;
        this.stepUp = stepUp;
        this.mfaStepUp = mfaStepUp;
        this.domainRegistry = domainRegistry;
    }

    private PrincipalDomain scope(Authentication auth) {
        return PrincipalDomain.of(auth, domainRegistry);
    }

    private static String actor(Authentication auth) {
        return auth == null ? "admin" : auth.getName();
    }

    // ── list (own domain; SUPERADMIN ?domain= filter) ────────────────────────────────────

    @PreAuthorize("hasAnyRole('ADMIN','SUPERADMIN')")
    @Operation(summary = "List", operationId = "backupAdminList")
    @GetMapping("")
    public Flux<BackupSet> list(@RequestParam(name = "domain", required = false)
                                @Size(max = 64) String domain, Authentication auth) {
        return service.list(scope(auth), domain);
    }

    // ── create (DOMAIN scope, own domain) ────────────────────────────────────────────────

    @PreAuthorize("hasAnyRole('ADMIN','SUPERADMIN')")
    @Operation(summary = "Create", operationId = "backupAdminCreate")
    @PostMapping("")
    public Mono<ResponseEntity<BackupSet>> create(@Valid @RequestBody CreateBackupRequest b,
                                                  Authentication auth) {
        BackupDestinationKind kind = BackupDestinationKind.from(b.destinationKind());
        if (kind == null) {
            return Mono.error(ApiException.badRequest(
                    "unknown destinationKind '" + b.destinationKind()
                            + "'; valid: object_store, node_storage"));
        }
        // DOMAIN scope only on the per-domain surface; TOTAL is the superadmin endpoint.
        return service.create(b.setKey(), BackupCloudScope.DOMAIN, b.services(), kind,
                        b.destinationRef(), b.encryptionMeta(), actor(auth), scope(auth))
                .map(ResponseEntity::ok)
                .onErrorResume(BackupService.TotalScopeDeniedException.class,
                        e -> Mono.error(ApiException.forbidden(e.getMessage())))
                .onErrorResume(IllegalArgumentException.class,
                        e -> Mono.error(ApiException.badRequest(e.getMessage())));
    }

    // ── version history ──────────────────────────────────────────────────────────────────

    @PreAuthorize("hasAnyRole('ADMIN','SUPERADMIN')")
    @Operation(summary = "Versions", operationId = "backupAdminVersions")
    @GetMapping("/{id}/versions")
    public Flux<BackupSet> versions(@PathVariable @NotBlank @Size(max = 36) String id,
                                    Authentication auth) {
        return service.versions(id, scope(auth));
    }

    // ── per-service artifact detail ──────────────────────────────────────────────────────

    @PreAuthorize("hasAnyRole('ADMIN','SUPERADMIN')")
    @Operation(summary = "Artifacts", operationId = "backupAdminArtifacts")
    @GetMapping("/{id}/artifacts")
    public Flux<BackupArtifact> artifacts(@PathVariable @NotBlank @Size(max = 36) String id,
                                          Authentication auth) {
        return service.artifacts(id, scope(auth));
    }

    // ── restore (PRIVILEGED: requires step-up) ───────────────────────────────────────────

    /**
     * Restore a backup set's version — the PRIVILEGED path. Requires a satisfied STEP-UP: the
     * caller presents a step-up token in the {@code X-Backup-StepUp} header; a missing/invalid
     * token is a clean 403 carrying the "requires step-up" contract. The set is re-resolved IN
     * SCOPE so a scoped admin can only restore their own brand's set (a cross-domain id is a
     * 404, not visible).
     */
    @PreAuthorize("hasAnyRole('ADMIN','SUPERADMIN')")
    @Operation(summary = "Restore", operationId = "backupAdminRestore")
    @PostMapping("/{id}/restore")
    public Mono<ResponseEntity<Map<String, Object>>> restore(
            @PathVariable @NotBlank @Size(max = 36) String id,
            @RequestHeader(name = BackupStepUpGate.STEP_UP_HEADER, required = false) String stepUpToken,
            @CookieValue(name = SessionCookieWebFilter.SESSION_COOKIE, required = false) String sessionCookie,
            @RequestHeader(name = HttpHeaders.AUTHORIZATION, required = false) String authHeader,
            Authentication auth) {
        String subject = actor(auth);
        // A5 UNIFIED step-up: the workload step-up token OR a FRESH Casdoor-MFA stamp on the
        // caller's opaque session. Restore is a SUPERADMIN NON-device op, so the MFA leg is
        // license-INDEPENDENT (no device_ssh_license needed). mfaStepUp.isFresh() is fail-closed
        // + flag-gated (app.casdoor.mfa.enabled=false by default -> only the token leg works).
        String sessionToken = SessionCookieWebFilter.bffTokenFrom(sessionCookie, authHeader);
        // Gate on MFA freshness then perform the step-up-gated restore.
        return mfaStepUp.isFresh(sessionToken)
                .flatMap(mfaFresh -> executeRestore(id, subject, stepUpToken, sessionToken,
                        mfaFresh, scope(auth)));
    }

    /** Enforce step-up gate then invoke the restore and map the result to a response. */
    private Mono<ResponseEntity<Map<String, Object>>> executeRestore(
            String id, String subject, String stepUpToken,
            String sessionToken, boolean mfaFresh, PrincipalDomain scope) {
        if (!stepUp.isSatisfied(subject, stepUpToken, mfaFresh)) {
            log.warn("[cloud-backup] DENY restore without step-up: set={} by={}", id, subject);
            return Mono.error(ApiException.forbidden(
                    "restore requires step-up: present a valid step-up token in the "
                            + BackupStepUpGate.STEP_UP_HEADER + " header"));
        }
        Mono<Void> consume = mfaFresh ? mfaStepUp.consume(sessionToken) : Mono.empty();
        return consume.then(service.restore(id, subject, scope))
                .map(set -> ResponseEntity.ok(Map.<String, Object>of(
                        "id", set.id(), "version", set.version(), "status", "RESTORE_QUEUED")))
                .onErrorResume(IllegalArgumentException.class,
                        e -> Mono.error(ApiException.notFound(e.getMessage())));
    }

    // ── per-service backup menu (running services) ───────────────────────────────────────

    @PreAuthorize("hasAnyRole('ADMIN','SUPERADMIN')")
    @Operation(summary = "Services", operationId = "backupAdminServices")
    @GetMapping("/services")
    public Flux<RunningService> services(Authentication auth) {
        return service.services(scope(auth));
    }

    // ── destination config ───────────────────────────────────────────────────────────────

    @PreAuthorize("hasAnyRole('ADMIN','SUPERADMIN')")
    @Operation(summary = "Get destination", operationId = "backupAdminGetDestination")
    @GetMapping("/destinations")
    public Mono<ResponseEntity<BackupDestination>> getDestination(
            @RequestParam(name = "domain", required = false) @Size(max = 64) String domain,
            Authentication auth) {
        return service.destination(scope(auth), domain)
                .map(ResponseEntity::ok)
                .defaultIfEmpty(ResponseEntity.noContent().build());
    }

    @PreAuthorize("hasAnyRole('ADMIN','SUPERADMIN')")
    @Operation(summary = "Put destination", operationId = "backupAdminPutDestination")
    @PutMapping("/destinations")
    public Mono<ResponseEntity<BackupDestination>> putDestination(
            @Valid @RequestBody BackupDestinationRequest b, Authentication auth) {
        BackupDestinationKind kind = BackupDestinationKind.from(b.kind());
        if (kind == null) {
            return Mono.error(ApiException.badRequest(
                    "unknown kind '" + b.kind() + "'; valid: object_store, node_storage"));
        }
        return service.putDestination(kind, b.destinationRef(), b.secretRef(), actor(auth),
                        scope(auth), b.targetDomain())
                .map(ResponseEntity::ok)
                .onErrorResume(IllegalArgumentException.class,
                        e -> Mono.error(ApiException.badRequest(e.getMessage())));
    }
}
