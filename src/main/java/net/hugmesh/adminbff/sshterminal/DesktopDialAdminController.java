package net.hugmesh.adminbff.sshterminal;

import io.swagger.v3.oas.annotations.Operation;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import net.hugmesh.authcore.casdoor.MfaStepUpService;
import net.hugmesh.authcore.config.SessionCookieWebFilter;
import net.hugmesh.adminbff.desktop.terminal.DeviceTerminalStepUpGate;
import net.hugmesh.commons.security.DomainRegistry;
import net.hugmesh.commons.security.PrincipalDomain;
import net.hugmesh.commons.web.ApiException;
import net.hugmesh.adminbff.web.StepUpRequiredException;
import net.hugmesh.adminbff.web.dto.DeviceSshDialResponse;

/**
 * The SUPERADMIN device-dial MANAGEMENT surface at {@code /bff/superadmin/desktop/dials} — the
 * runtime control that flips a seeded PENDING {@code device_ssh_dial} row to ACTIVE (making
 * {@code app.device-terminal.dial.enabled} actually usable) and revokes it. Closes the verified
 * {@code canDial()} dead-end.
 *
 * <h3>Authorization</h3>
 * Under the coarse {@code /bff/superadmin/**} gate ({@code hasRole('SUPERADMIN')}); every mutation
 * also carries {@code @PreAuthorize("hasRole('SUPERADMIN')")}. Activating/revoking a dial key onto a
 * device is a MESH-TRUST operation, NOT a per-domain license, so it is SUPERADMIN-only. The mutations
 * additionally require a valid step-up token on the SAME
 * {@link DeviceTerminalStepUpGate#STEP_UP_HEADER X-Device-Terminal-StepUp} header (they change dial
 * trust state) — missing/blank → 403. The A5 UNIFIED step-up applies here too: EITHER the workload
 * step-up token OR a FRESH Casdoor-MFA stamp on the caller's opaque session (co-equal legs, mirroring
 * {@code BackupAdminController} / {@code DesktopRemoteInstallController}). Returns ONLY the NON-SECRET
 * {@link DeviceSshDialResponse} (never key bytes). A scoped list never leaks foreign-domain rows
 * (defence-in-depth; SUPERADMIN is unscoped so it is the live path). Activation REFUSES an unpinned
 * row (422) and 503s while the dial leg ships dark.
 *
 * <ul>
 *   <li>{@code GET  /bff/superadmin/desktop/dials} — scoped list (non-secret).</li>
 *   <li>{@code GET  /bff/superadmin/desktop/dials/{deviceId}} — one row (non-secret).</li>
 *   <li>{@code POST /bff/superadmin/desktop/dials/{deviceId}/activate} — PENDING→ACTIVE (+gen bump).</li>
 *   <li>{@code POST /bff/superadmin/desktop/dials/{deviceId}/revoke} — ACTIVE→REVOKED (CAS +gen bump).</li>
 * </ul>
 */
@RestController
@RequestMapping("/bff/superadmin/desktop/dials")
@Validated
public class DesktopDialAdminController {

    private static final Logger log = LoggerFactory.getLogger(DesktopDialAdminController.class);
    private static final int MAX_ID = 36;

    /** ONE generic message for an absent/cross dial row (anti-enumeration). */
    static final String GENERIC_DIAL_NOT_FOUND = "no such dial";

    private final DesktopDialService service;
    private final DeviceTerminalStepUpGate stepUp;
    private final MfaStepUpService mfaStepUp;
    private final DomainRegistry domainRegistry;

    public DesktopDialAdminController(DesktopDialService service,
                                      DeviceTerminalStepUpGate stepUp,
                                      MfaStepUpService mfaStepUp,
                                      DomainRegistry domainRegistry) {
        this.service = service;
        this.stepUp = stepUp;
        this.mfaStepUp = mfaStepUp;
        this.domainRegistry = domainRegistry;
    }

    private PrincipalDomain scope(Authentication auth) {
        return PrincipalDomain.of(auth, domainRegistry);
    }

    private static String subject(Authentication auth) {
        if (auth != null && auth.getPrincipal() instanceof Jwt jwt) {
            return jwt.getSubject();
        }
        return auth == null ? null : auth.getName();
    }

    // ── list (scoped; non-secret) ─────────────────────────────────────────────────
    @PreAuthorize("hasRole('SUPERADMIN')")
    @Operation(summary = "List", operationId = "desktopDialAdminList")
    @GetMapping
    public Flux<DeviceSshDialResponse> list(Authentication auth) {
        return service.list(scope(auth)).map(DeviceSshDialResponse::of);
    }

    // ── one row (non-secret) ────────────────────────────────────────────────────
    @PreAuthorize("hasRole('SUPERADMIN')")
    @Operation(summary = "Get", operationId = "desktopDialAdminGet")
    @GetMapping("/{deviceId}")
    public Mono<DeviceSshDialResponse> get(
            @PathVariable @NotBlank @Size(max = MAX_ID) String deviceId) {
        return service.findByDevice(deviceId)
                .map(DeviceSshDialResponse::of)
                .switchIfEmpty(Mono.error(ApiException.notFound(GENERIC_DIAL_NOT_FOUND)));
    }

    // ── activate (PENDING -> ACTIVE; step-up; 422 if unpinned; 503 while dark) ────
    @PreAuthorize("hasRole('SUPERADMIN')")
    @Operation(summary = "Activate", operationId = "desktopDialAdminActivate")
    @PostMapping("/{deviceId}/activate")
    public Mono<DeviceSshDialResponse> activate(
            @PathVariable @NotBlank @Size(max = MAX_ID) String deviceId,
            @RequestHeader(value = DeviceTerminalStepUpGate.STEP_UP_HEADER, required = false) String stepUpToken,
            @CookieValue(name = SessionCookieWebFilter.SESSION_COOKIE, required = false) String sessionCookie,
            @RequestHeader(name = HttpHeaders.AUTHORIZATION, required = false) String authHeader,
            Authentication auth) {
        String by = subject(auth);
        // A5 UNIFIED step-up: the workload step-up token OR a FRESH Casdoor-MFA stamp on the
        // caller's opaque session. Dial activation is a MESH-TRUST op, not a per-device license, so
        // the MFA leg satisfies the step-up re-confirmation same as the token leg does.
        // mfaStepUp.isFresh() is flag-gated + fail-closed (app.casdoor.mfa.enabled=false by default
        // -> only the token leg works).
        String sessionToken = SessionCookieWebFilter.bffTokenFrom(sessionCookie, authHeader);
        return mfaStepUp.isFresh(sessionToken)
                .flatMap(mfaFresh -> executeActivate(deviceId, by, stepUpToken, sessionToken, mfaFresh));
    }

    /** Enforce the unified step-up gate then invoke the activate service call. */
    private Mono<DeviceSshDialResponse> executeActivate(String deviceId, String by, String stepUpToken,
                                                        String sessionToken, boolean mfaFresh) {
        if (!stepUp.isSatisfied(by, stepUpToken, mfaFresh)) {
            return Mono.error(StepUpRequiredException.forRetryHeader(
                    DeviceTerminalStepUpGate.STEP_UP_HEADER, "dial activation"));
        }
        return service.activate(deviceId, by)
                .map(DeviceSshDialResponse::of)
                .doOnSuccess(r -> {
                    stepUp.consume(by);
                    if (mfaFresh) {
                        mfaStepUp.consume(sessionToken).subscribe();
                    }
                })
                .onErrorResume(DesktopDialService.DialDarkException.class,
                        e -> Mono.error(ApiException.serviceUnavailable(e.getMessage())))
                .onErrorResume(DesktopDialService.DialUnpinnedException.class,
                        e -> Mono.error(ApiException.unprocessable(e.getMessage())))
                .onErrorResume(DesktopDialService.DialNotFoundException.class, e -> {
                    log.warn("[desktop-dial] activate DENY (audit) device={} cause={}", deviceId, e.getMessage());
                    return Mono.error(ApiException.notFound(GENERIC_DIAL_NOT_FOUND));
                });
    }

    // ── revoke (ACTIVE -> REVOKED CAS; step-up; allowed while dark) ───────────────
    @PreAuthorize("hasRole('SUPERADMIN')")
    @Operation(summary = "Revoke", operationId = "desktopDialAdminRevoke")
    @PostMapping("/{deviceId}/revoke")
    public Mono<DeviceSshDialResponse> revoke(
            @PathVariable @NotBlank @Size(max = MAX_ID) String deviceId,
            @RequestHeader(value = DeviceTerminalStepUpGate.STEP_UP_HEADER, required = false) String stepUpToken,
            @CookieValue(name = SessionCookieWebFilter.SESSION_COOKIE, required = false) String sessionCookie,
            @RequestHeader(name = HttpHeaders.AUTHORIZATION, required = false) String authHeader,
            Authentication auth) {
        String by = subject(auth);
        // A5 UNIFIED step-up: same co-equal token-OR-fresh-MFA leg as activate() above.
        String sessionToken = SessionCookieWebFilter.bffTokenFrom(sessionCookie, authHeader);
        return mfaStepUp.isFresh(sessionToken)
                .flatMap(mfaFresh -> executeRevoke(deviceId, by, stepUpToken, sessionToken, mfaFresh));
    }

    /** Enforce the unified step-up gate then invoke the revoke service call. */
    private Mono<DeviceSshDialResponse> executeRevoke(String deviceId, String by, String stepUpToken,
                                                      String sessionToken, boolean mfaFresh) {
        if (!stepUp.isSatisfied(by, stepUpToken, mfaFresh)) {
            return Mono.error(StepUpRequiredException.forRetryHeader(
                    DeviceTerminalStepUpGate.STEP_UP_HEADER, "dial revoke"));
        }
        return service.revoke(deviceId, by)
                .map(DeviceSshDialResponse::of)
                .doOnSuccess(r -> {
                    stepUp.consume(by);
                    if (mfaFresh) {
                        mfaStepUp.consume(sessionToken).subscribe();
                    }
                })
                .onErrorResume(DesktopDialService.DialNotFoundException.class, e -> {
                    log.warn("[desktop-dial] revoke DENY (audit) device={} cause={}", deviceId, e.getMessage());
                    return Mono.error(ApiException.notFound(GENERIC_DIAL_NOT_FOUND));
                });
    }
}
