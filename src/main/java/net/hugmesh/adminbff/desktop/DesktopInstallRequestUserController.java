package net.hugmesh.adminbff.desktop;

import io.swagger.v3.oas.annotations.Operation;

import jakarta.validation.Valid;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import net.hugmesh.commons.security.DomainRegistry;
import net.hugmesh.commons.security.PrincipalDomain;
import net.hugmesh.commons.web.ApiException;
import net.hugmesh.adminbff.web.dto.DesktopInstallRequestSubmit;

/**
 * The user-facing DESKTOP INSTALL-REQUEST surface at {@code /bff/desktop/install-requests} —
 * any AUTHENTICATED desktop user may ask their admin to allow/install an app, and may list
 * THEIR OWN requests.
 *
 * <h3>owner == subject (fail-closed)</h3>
 * The coarse gate ({@code SecurityConfig.commonRoutes}) on
 * {@code /bff/desktop/install-requests/**} is {@code authenticated()}. The {@code requester}
 * is taken from {@code jwt.getSubject()} and the {@code domain} from the validated issuer
 * (via {@link PrincipalDomain}) — NEVER body fields. The user read is double-scoped (requester +
 * domain) in the repository, so a user can ONLY ever see their OWN requests; there is no path
 * for a user to read or act on another user's request (the admin inbox + decide is the
 * separate {@code /bff/admin/desktop/install-requests} surface). A token with no resolvable
 * subject/tenant fails closed (401 upstream / NO_DOMAIN sentinel matches nothing).
 */
@RestController
@RequestMapping("/bff/desktop/install-requests")
@Validated
public class DesktopInstallRequestUserController {

    private static final Logger log = LoggerFactory.getLogger(DesktopInstallRequestUserController.class);

    private final DesktopInstallRequestService service;
    private final DomainRegistry domainRegistry;

    public DesktopInstallRequestUserController(DesktopInstallRequestService service,
                                               DomainRegistry domainRegistry) {
        this.service = service;
        this.domainRegistry = domainRegistry;
    }

    private static String subject(Authentication auth) {
        if (auth != null && auth.getPrincipal() instanceof Jwt jwt) {
            return jwt.getSubject();
        }
        return auth == null ? null : auth.getName();
    }

    private String domain(Authentication auth) {
        return PrincipalDomain.of(auth, domainRegistry).domain();
    }

    /** Submit a request (owner == subject; requester + domain are caller-derived). */
    @PreAuthorize("isAuthenticated()")
    @Operation(summary = "Submit", operationId = "desktopInstallRequestUserSubmit")
    @PostMapping("")
    @ResponseStatus(HttpStatus.CREATED)
    public Mono<DesktopInstallRequest> submit(@Valid @RequestBody DesktopInstallRequestSubmit b,
                                              Authentication auth) {
        String requester = subject(auth);
        if (requester == null || requester.isBlank()) {
            return Mono.error(ApiException.unauthorized("no subject on token"));
        }
        return service.submit(requester, b.appRef(), b.deviceId(), domain(auth))
                .doOnNext(r -> log.info("[desktop-install-req] user submit by={} ref={}", requester, b.appRef()));
    }

    /** The caller's OWN requests (owner == subject). A user never sees another user's. */
    @PreAuthorize("isAuthenticated()")
    @Operation(summary = "Mine", operationId = "desktopInstallRequestUserMine")
    @GetMapping("")
    public Flux<DesktopInstallRequest> mine(Authentication auth) {
        String requester = subject(auth);
        if (requester == null || requester.isBlank()) {
            return Flux.error(ApiException.unauthorized("no subject on token"));
        }
        return service.listMine(requester, domain(auth));
    }
}
