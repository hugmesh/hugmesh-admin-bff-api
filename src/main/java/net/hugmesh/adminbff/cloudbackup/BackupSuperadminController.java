package net.hugmesh.adminbff.cloudbackup;

import io.swagger.v3.oas.annotations.Operation;

import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;
import net.hugmesh.commons.security.DomainRegistry;
import net.hugmesh.commons.security.PrincipalDomain;
import net.hugmesh.commons.web.ApiException;
import net.hugmesh.adminbff.web.dto.CreateBackupRequest;

/**
 * The TOTAL-CLOUD backup surface (SUPERADMIN-only) at
 * {@code /bff/superadmin/cloud-backups/total}. A total-cloud backup captures every brand's
 * state at once (the infra control plane), so it is restricted to the cross-domain super-role.
 *
 * <h3>Authorization (triple-gated, fail-closed)</h3>
 * <ol>
 *   <li>the {@code /bff/superadmin/**} coarse path gate ({@code hasRole('SUPERADMIN')}) —
 *       an ADMIN never even reaches this controller;</li>
 *   <li>the per-method {@code @PreAuthorize("hasRole('SUPERADMIN')")};</li>
 *   <li>the service-layer {@code scope.scoped()} check that rejects a TOTAL-scope create by a
 *       non-superadmin ({@link BackupService.TotalScopeDeniedException} -> 403) as
 *       defence-in-depth.</li>
 * </ol>
 *
 * The {@code domain} on the total set is the superadmin's home domain (the row it writes); the
 * set is read CROSS-DOMAIN by the superadmin. {@code createdBy} = the superadmin's JWT subject.
 */
@RestController
@RequestMapping("/bff/superadmin/cloud-backups")
@Validated
public class BackupSuperadminController {

    private final BackupService service;
    private final DomainRegistry domainRegistry;

    public BackupSuperadminController(BackupService service, DomainRegistry domainRegistry) {
        this.service = service;
        this.domainRegistry = domainRegistry;
    }

    private PrincipalDomain scope(Authentication auth) {
        return PrincipalDomain.of(auth, domainRegistry);
    }

    private static String actor(Authentication auth) {
        return auth == null ? "superadmin" : auth.getName();
    }

    /** Create a TOTAL-CLOUD (scope=TOTAL) backup — SUPERADMIN-only. */
    @PreAuthorize("hasRole('SUPERADMIN')")
    @Operation(summary = "Create total", operationId = "backupSuperadminCreateTotal")
    @PostMapping("/total")
    public Mono<ResponseEntity<BackupSet>> createTotal(@Valid @RequestBody CreateBackupRequest b,
                                                       Authentication auth) {
        BackupDestinationKind kind = BackupDestinationKind.from(b.destinationKind());
        if (kind == null) {
            return Mono.error(ApiException.badRequest(
                    "unknown destinationKind '" + b.destinationKind()
                            + "'; valid: object_store, node_storage"));
        }
        return service.create(b.setKey(), BackupCloudScope.TOTAL, b.services(), kind,
                        b.destinationRef(), b.encryptionMeta(), actor(auth), scope(auth))
                .map(ResponseEntity::ok)
                .onErrorResume(BackupService.TotalScopeDeniedException.class,
                        e -> Mono.error(ApiException.forbidden(e.getMessage())))
                .onErrorResume(IllegalArgumentException.class,
                        e -> Mono.error(ApiException.badRequest(e.getMessage())));
    }
}
