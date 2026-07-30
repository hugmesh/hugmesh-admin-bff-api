package systems.hugmesh.adminbff.desktop;

import io.swagger.v3.oas.annotations.Operation;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import systems.hugmesh.commons.security.DomainRegistry;
import systems.hugmesh.commons.security.PrincipalDomain;
import systems.hugmesh.commons.web.ApiException;
import systems.hugmesh.adminbff.web.dto.DesktopSudoGrantRequest;

import java.util.Map;

/**
 * The DESKTOP SUDO grant surface (ADMIN/SUPERADMIN) at {@code /bff/admin/desktop/sudo} —
 * the source of truth for which desktop user holds SSO-enforced sudo on which device.
 * DEFAULT NONE: absent an active grant, the user has no sudo; an active grant is emitted as
 * a revocable SSO claim. Revoke is a CAS {@code active -> revoked} (never deleted = audit).
 *
 * <h3>Authorization</h3>
 * Mounted under {@code /bff/admin/**} (coarse gate {@code hasAnyRole('ADMIN','SUPERADMIN')});
 * each method carries {@code @PreAuthorize("hasAnyRole('ADMIN','SUPERADMIN')")}. MOD/USER →
 * 403. The ADMIN read is own-domain via {@link PrincipalDomain} (validated issuer); SUPERADMIN
 * unscoped. The entitlement-READ the IdP/desktop consults is a SEPARATE internal-mTLS
 * endpoint ({@link DesktopSudoEntitlementController}), never reachable by a user JWT.
 */
@RestController
@RequestMapping("/bff/admin/desktop/sudo")
@Validated
public class DesktopSudoAdminController {

    private static final Logger log = LoggerFactory.getLogger(DesktopSudoAdminController.class);

    private final DesktopSudoGrantService service;
    private final DomainRegistry domainRegistry;

    public DesktopSudoAdminController(DesktopSudoGrantService service, DomainRegistry domainRegistry) {
        this.service = service;
        this.domainRegistry = domainRegistry;
    }

    private PrincipalDomain scope(Authentication auth) {
        return PrincipalDomain.of(auth, domainRegistry);
    }

    private static String actor(Authentication auth) {
        return auth == null ? "superadmin" : auth.getName();
    }

    /** The sudo grants visible to the acting admin (own brand; SUPERADMIN all). */
    @PreAuthorize("hasAnyRole('ADMIN','SUPERADMIN')")
    @Operation(summary = "List", operationId = "desktopSudoAdminList")
    @GetMapping("")
    public Flux<DesktopSudoGrant> list(Authentication auth) {
        return service.list(scope(auth));
    }

    /** Grant a desktop user sudo on a device (idempotent; domain stamped from the device's
     *  residency). A SUPERADMIN-owned device target is a clean 422, and a SCOPED admin
     *  granting on another brand's device is denied (own-domain wall, parity with revoke/list
     *  and remote-install). The acting admin must ALSO hold an active device-ssh-license for
     *  the target device (parity with remote-install); that denial surfaces as a 403 (the same
     *  status family as the remote-install license denial), distinct from the 422 own-domain/
     *  superadmin-owned denials. */
    @PreAuthorize("hasAnyRole('ADMIN','SUPERADMIN')")
    @Operation(summary = "Grant", operationId = "desktopSudoAdminGrant")
    @PostMapping("/grant")
    public Mono<ResponseEntity<DesktopSudoGrant>> grant(
            @Valid @RequestBody DesktopSudoGrantRequest b, Authentication auth) {
        return service.grant(b.subject(), b.deviceId(), actor(auth), scope(auth))
                .doOnNext(g -> log.info("[desktop-sudo] grant subject={} device={} by={}",
                        b.subject(), b.deviceId(), actor(auth)))
                .map(ResponseEntity::ok)
                .onErrorResume(DesktopRemoteInstallService.RemoteInstallDeniedException.class,
                        e -> Mono.error(ApiException.forbidden(e.getMessage())))
                .onErrorResume(IllegalArgumentException.class,
                        e -> Mono.error(ApiException.unprocessable(e.getMessage())));
    }

    /** Revoke a sudo grant by id (CAS audit + gen bump). Removes the SSO claim at refresh. */
    @PreAuthorize("hasAnyRole('ADMIN','SUPERADMIN')")
    @Operation(summary = "Revoke", operationId = "desktopSudoAdminRevoke")
    @DeleteMapping("/{grantId}")
    public Mono<ResponseEntity<Map<String, Object>>> revoke(
            @PathVariable @NotBlank @Size(max = 36) String grantId, Authentication auth) {
        return service.revoke(grantId, actor(auth), scope(auth))
                .map(n -> ResponseEntity.ok(Map.of("revoked", n)));
    }
}
