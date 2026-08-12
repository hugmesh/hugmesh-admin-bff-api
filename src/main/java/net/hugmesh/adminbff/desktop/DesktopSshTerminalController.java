package net.hugmesh.adminbff.desktop;

import io.swagger.v3.oas.annotations.Operation;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;
import net.hugmesh.adminbff.desktop.terminal.DeviceSshTerminalWebSocketHandler;
import net.hugmesh.adminbff.desktop.terminal.DeviceTerminalProperties;
import net.hugmesh.commons.security.DomainRegistry;
import net.hugmesh.commons.security.PrincipalDomain;
import net.hugmesh.commons.web.ApiException;
import net.hugmesh.adminbff.web.dto.DesktopSshSessionDescriptor;

/**
 * The pre-WS SESSION-DESCRIPTOR endpoint (ADMIN/SUPERADMIN) at
 * {@code POST /bff/admin/desktop/ssh-terminal/sessions} — the SINGLE place the UI learns the REAL
 * live device-terminal WebSocket coordinates before opening the socket.
 *
 * <p>It is NOT a second WS route; the ONE live transport is the
 * {@link DeviceSshTerminalWebSocketHandler} mounted at
 * {@code /bff/admin/device-terminal/{deviceId}}. This endpoint validates the SAME own-domain
 * device-ssh-license authorization the socket re-verifies (so a descriptor is only returned to a
 * caller who could actually open the socket) and returns a typed
 * {@link DesktopSshSessionDescriptor} carrying the REAL {@code wsPath}, the {@code dark} flag (driven
 * by {@code app.device-terminal.enabled}), and {@code stepUpRequired:true}. This fixes the UI/BFF
 * path drift at the source (the UI no longer hardcodes a path).
 *
 * <h3>Authorization (fail-closed; rides device-ssh-license)</h3>
 * Coarse gate {@code /bff/admin/**} ({@code hasAnyRole('ADMIN','SUPERADMIN')}); reuses
 * {@link DesktopRemoteInstallService#authorizeTerminal} (own-domain wall + SUPERADMIN-owned-node
 * guard + active device-OR-domain ssh-license). operator = {@code jwt.getSubject()} (never a body
 * field); domain from the cryptographically-validated issuer. EVERY device-targeting denial
 * collapses to ONE generic 403 (anti-enumeration — a scoped admin must not learn whether a foreign
 * device exists / its residency / its ownership); the specific cause stays in a server-side WARN
 * audit. The descriptor is non-secret and carries NO token (the UI mints one via
 * {@code /bff/admin/desktop/step-up}). The WS itself re-verifies all five gates regardless.
 */
@RestController
@RequestMapping("/bff/admin/desktop/ssh-terminal")
@Validated
public class DesktopSshTerminalController {

    private static final Logger log = LoggerFactory.getLogger(DesktopSshTerminalController.class);

    /** The ONE generic, non-distinguishing 403 message for EVERY device-targeting denial
     *  (not-registered / cross-domain / superadmin-owned / no-license) — anti-enumeration. The
     *  specific cause is preserved server-side only (the service logs a WARN audit line). */
    static final String GENERIC_DENY = "not authorized for this device";

    private final DesktopRemoteInstallService remoteInstall;
    private final DomainRegistry domainRegistry;
    private final DeviceTerminalProperties terminalProps;

    public DesktopSshTerminalController(DesktopRemoteInstallService remoteInstall,
                                        DomainRegistry domainRegistry,
                                        DeviceTerminalProperties terminalProps) {
        this.remoteInstall = remoteInstall;
        this.domainRegistry = domainRegistry;
        this.terminalProps = terminalProps;
    }

    private PrincipalDomain scope(Authentication auth) {
        return PrincipalDomain.of(auth, domainRegistry);
    }

    private static String operator(Authentication auth) {
        if (auth != null && auth.getPrincipal() instanceof Jwt jwt) {
            return jwt.getSubject();
        }
        return auth == null ? null : auth.getName();
    }

    /**
     * Authorize + return the pre-WS descriptor for {@code deviceId}: validates the same
     * device-ssh-license authorization the live socket re-verifies, then returns the REAL
     * {@link DesktopSshSessionDescriptor#wsPath() wsPath} + {@code dark} + {@code stepUpRequired}.
     * Any device-targeting denial is a generic 403 (anti-enumeration).
     */
    @PreAuthorize("hasAnyRole('ADMIN','SUPERADMIN')")
    @Operation(summary = "Open session", operationId = "desktopSshTerminalOpenSession")
    @PostMapping("/sessions")
    public Mono<DesktopSshSessionDescriptor> openSession(
            @RequestParam @NotBlank @Size(max = 36) String deviceId, Authentication auth) {
        String operator = operator(auth);
        if (operator == null || operator.isBlank()) {
            return Mono.error(ApiException.unauthorized("no subject on token"));
        }
        return remoteInstall.authorizeTerminal(operator, deviceId, scope(auth))
                // Authorized — build the session descriptor with WS path and dark-mode status.
                .then(Mono.fromSupplier(() -> buildSessionDescriptor(operator, deviceId)))
                .onErrorResume(DesktopRemoteInstallService.RemoteInstallDeniedException.class, e -> {
                    // Collapse EVERY distinct device-targeting denial to ONE generic 403; the
                    // specific cause stays in the service-side WARN audit (anti-enumeration).
                    log.warn("[desktop-ssh-terminal] DENY (audit) operator={} device={} cause={}",
                            operator, deviceId, e.getMessage());
                    return Mono.error(ApiException.forbidden(GENERIC_DENY));
                });
    }

    /** Build the session descriptor once authorization has passed, logging the outcome. */
    private DesktopSshSessionDescriptor buildSessionDescriptor(String operator, String deviceId) {
        boolean dark = !terminalProps.isEnabled();
        String wsPath = DeviceSshTerminalWebSocketHandler.WS_PATH_PREFIX + deviceId;
        log.info("[desktop-ssh-terminal] authorized descriptor operator={} device={} "
                + "wsPath={} dark={}", operator, deviceId, wsPath, dark);
        return new DesktopSshSessionDescriptor(deviceId, dark, wsPath, true,
                dark ? "device terminal ships dark (app.device-terminal.enabled=false) — "
                        + "authorization is live; open the WS at wsPath with a step-up token "
                        + "once enabled"
                     : "open the WS at wsPath with a step-up token "
                        + "(X-Device-Terminal-StepUp header or stepup.<token> subprotocol)");
    }
}
