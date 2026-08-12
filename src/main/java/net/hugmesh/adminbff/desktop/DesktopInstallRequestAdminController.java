package net.hugmesh.adminbff.desktop;

import io.swagger.v3.oas.annotations.Operation;

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
import net.hugmesh.commons.security.DomainRegistry;
import net.hugmesh.commons.security.PrincipalDomain;
import net.hugmesh.commons.web.ApiException;

import java.util.Map;
import java.util.Set;

/**
 * The admin DESKTOP INSTALL-REQUEST inbox at {@code /bff/admin/desktop/install-requests} —
 * ADMIN/SUPERADMIN list the brand's requests and decide them (approve / deny / installed).
 *
 * <h3>Authorization</h3>
 * Mounted under {@code /bff/admin/**} (coarse gate {@code hasAnyRole('ADMIN','SUPERADMIN')});
 * each method carries {@code @PreAuthorize("hasAnyRole('ADMIN','SUPERADMIN')")}. MOD/USER →
 * 403. The inbox + decide are brand-scoped via {@link PrincipalDomain} (validated issuer): a
 * scoped admin can only see/decide their own brand's requests; SUPERADMIN unscoped. Decide is
 * a single-winner CAS {@code pending -> terminal}.
 */
@RestController
@RequestMapping("/bff/admin/desktop/install-requests")
@Validated
public class DesktopInstallRequestAdminController {

    private static final Logger log = LoggerFactory.getLogger(DesktopInstallRequestAdminController.class);

    /** The terminal statuses an admin may decide a request into. */
    private static final Set<String> DECIDABLE = Set.of(
            DesktopInstallRequest.STATUS_APPROVED,
            DesktopInstallRequest.STATUS_DENIED,
            DesktopInstallRequest.STATUS_INSTALLED);

    private final DesktopInstallRequestService service;
    private final DomainRegistry domainRegistry;

    public DesktopInstallRequestAdminController(DesktopInstallRequestService service,
                                                DomainRegistry domainRegistry) {
        this.service = service;
        this.domainRegistry = domainRegistry;
    }

    private PrincipalDomain scope(Authentication auth) {
        return PrincipalDomain.of(auth, domainRegistry);
    }

    private static String actor(Authentication auth) {
        return auth == null ? "superadmin" : auth.getName();
    }

    /** The brand's request inbox (own brand; SUPERADMIN all). */
    @PreAuthorize("hasAnyRole('ADMIN','SUPERADMIN')")
    @Operation(summary = "List", operationId = "desktopInstallRequestAdminList")
    @GetMapping("")
    public Flux<DesktopInstallRequest> list(Authentication auth) {
        return service.listForAdmin(scope(auth));
    }

    /**
     * Decide a request: {@code POST /{id}/decide?status=approved|denied|installed}. CAS
     * {@code pending -> status}, brand-scoped, single-winner. An unknown status is a 400; a
     * no-op (already decided / absent / out of scope) returns {@code decided:0}.
     */
    @PreAuthorize("hasAnyRole('ADMIN','SUPERADMIN')")
    @Operation(summary = "Decide", operationId = "desktopInstallRequestAdminDecide")
    @PostMapping("/{id}/decide")
    public Mono<ResponseEntity<Map<String, Object>>> decide(
            @PathVariable @NotBlank @Size(max = 36) String id,
            @RequestParam @NotBlank @Size(max = 16) String status,
            Authentication auth) {
        String s = status.trim().toLowerCase();
        if (!DECIDABLE.contains(s)) {
            return Mono.error(ApiException.badRequest(
                    "status must be one of approved|denied|installed"));
        }
        return service.decide(id, s, actor(auth), scope(auth))
                .doOnNext(n -> log.info("[desktop-install-req] admin decide id={} -> {} by={} rows={}",
                        id, s, actor(auth), n))
                .map(n -> ResponseEntity.ok(Map.of("decided", n, "status", s)));
    }
}
