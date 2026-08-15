package net.hugmesh.adminbff.desktop;

import io.swagger.v3.oas.annotations.Operation;

import jakarta.validation.Valid;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;
import net.hugmesh.authcore.casdoor.MfaStepUpService;
import net.hugmesh.authcore.config.SessionCookieWebFilter;
import net.hugmesh.adminbff.desktop.terminal.DeviceTerminalStepUpGate;
import net.hugmesh.commons.security.DomainRegistry;
import net.hugmesh.commons.security.PrincipalDomain;
import net.hugmesh.commons.web.ApiException;
import net.hugmesh.adminbff.web.StepUpRequiredException;
import net.hugmesh.adminbff.web.dto.DesktopRemoteInstallRequest;

/**
 * The REMOTE-INSTALL trigger (ADMIN/SUPERADMIN) at
 * {@code /bff/admin/desktop/remote-install} — the one-click install that RIDES the admin's
 * device-SSH license, now STEP-UP-GATED to match the in-UI SSH terminal (a fail-closed tightening:
 * remote-install reaches an eventual exec onto a tenant device, so it requires the SAME deliberate
 * step-up the terminal does).
 *
 * <h3>Authorization (fail-closed; rides device-ssh-license + step-up)</h3>
 * Mounted under {@code /bff/admin/**} (coarse gate {@code hasAnyRole('ADMIN','SUPERADMIN')}); the
 * method carries {@code @PreAuthorize("hasAnyRole('ADMIN','SUPERADMIN')")}. ON TOP:
 * <ol>
 *   <li><b>Step-up</b> — the request must carry a valid step-up token on the SAME
 *       {@link DeviceTerminalStepUpGate#STEP_UP_HEADER X-Device-Terminal-StepUp} header the terminal
 *       uses (mirrors the {@code ImageBuildController} idiom). Missing/blank/invalid → 403 even for
 *       an otherwise-authorized ADMIN. The token is consumed single-use AFTER the full authz pass
 *       (so a denied attempt never burns it).</li>
 *   <li><b>Device-ssh-license + tenancy</b> — {@link DesktopRemoteInstallService}: registered +
 *       own-domain wall + SUPERADMIN-owned-node guard + active device-OR-domain ssh-license +
 *       ref-in-enabled-allowlist. operator = {@code jwt.getSubject()} (never a body field); domain
 *       from the validated issuer. EVERY device-targeting denial collapses to ONE generic 403
 *       (anti-enumeration); the specific cause stays in a server-side WARN audit. The SSH exec
 *       itself ships DARK behind the Noop.</li>
 * </ol>
 *
 * <p><b>Two-key trust model.</b> When live, the BFF dials the device as {@code device_ssh_dial.dial_user}
 * with the Vault/ESO-mounted dial key (the operator's #84-issued client key is NOT the BFF→device
 * credential); operator accountability lives in this audit + the step-up consume.
 */
@RestController
@RequestMapping("/bff/admin/desktop/remote-install")
@Validated
public class DesktopRemoteInstallController {

    private static final Logger log = LoggerFactory.getLogger(DesktopRemoteInstallController.class);

    /** The ONE generic, non-distinguishing 403 message for EVERY device-targeting denial — same as
     *  the descriptor controller (anti-enumeration; specific cause stays server-side). */
    static final String GENERIC_DENY = "not authorized for this device";

    private final DesktopRemoteInstallService service;
    private final DeviceTerminalStepUpGate stepUp;
    private final MfaStepUpService mfaStepUp;
    private final DomainRegistry domainRegistry;

    public DesktopRemoteInstallController(DesktopRemoteInstallService service,
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

    /** The acting admin's Casdoor subject — the ssh-license operator key (never a body field). */
    private static String operator(Authentication auth) {
        if (auth != null && auth.getPrincipal() instanceof Jwt jwt) {
            return jwt.getSubject();
        }
        return auth == null ? null : auth.getName();
    }

    @PreAuthorize("hasAnyRole('ADMIN','SUPERADMIN')")
    @Operation(summary = "Remote install", operationId = "desktopRemoteInstallRemoteInstall")
    @PostMapping("")
    public Mono<String> remoteInstall(
            @Valid @RequestBody DesktopRemoteInstallRequest b,
            @RequestHeader(value = DeviceTerminalStepUpGate.STEP_UP_HEADER, required = false) String stepUpToken,
            @CookieValue(name = SessionCookieWebFilter.SESSION_COOKIE, required = false) String sessionCookie,
            @RequestHeader(name = HttpHeaders.AUTHORIZATION, required = false) String authHeader,
            Authentication auth) {
        String operator = operator(auth);
        if (operator == null || operator.isBlank()) {
            return Mono.error(ApiException.unauthorized("no subject on token"));
        }
        // A5 UNIFIED step-up FIRST (fail-closed): the workload step-up token OR a FRESH
        // Casdoor-MFA stamp. remote-install is a DEVICE op — the MFA leg only satisfies the
        // step-up RE-CONFIRMATION; the device_ssh_license precondition is STILL enforced
        // DOWNSTREAM by DesktopRemoteInstallService (own-domain + active license), so a fresh
        // MFA stamp does NOT bypass the license. mfaStepUp.isFresh() is flag-gated +
        // fail-closed (app.casdoor.mfa.enabled=false by default -> only the token leg works).
        String sessionToken = SessionCookieWebFilter.bffTokenFrom(sessionCookie, authHeader);
        // Gate on MFA freshness then execute the step-up-gated remote install.
        return mfaStepUp.isFresh(sessionToken)
                .flatMap(mfaFresh -> executeRemoteInstall(operator, b, stepUpToken,
                        sessionToken, mfaFresh, scope(auth)));
    }

    /** Enforce step-up gate then invoke the remote-install service with a single-use consume callback. */
    private Mono<String> executeRemoteInstall(String operator, DesktopRemoteInstallRequest b,
                                              String stepUpToken, String sessionToken,
                                              boolean mfaFresh, PrincipalDomain scope) {
        if (!stepUp.isSatisfied(operator, stepUpToken, mfaFresh)) {
            return Mono.error(StepUpRequiredException.forRetryHeader(
                    DeviceTerminalStepUpGate.STEP_UP_HEADER, "remote-install"));
        }
        // Consume the single-use token/freshness ONLY after the full device authz pass — a denied
        // attempt never burns it; the MFA freshness is consumed in the same callback.
        return service.remoteInstall(operator, b.deviceId(), b.appRef(), scope,
                        () -> {
                            stepUp.consume(operator);
                            if (mfaFresh) {
                                mfaStepUp.consume(sessionToken).subscribe();
                            }
                        })
                .doOnNext(r -> log.info("[desktop-remote-install] trigger operator={} device={} ref={}",
                        operator, b.deviceId(), b.appRef()))
                .onErrorResume(DesktopRemoteInstallService.RemoteInstallDeniedException.class, e -> {
                    // Collapse every device-targeting denial to ONE generic 403; cause stays server-side.
                    log.warn("[desktop-remote-install] DENY (audit) operator={} device={} cause={}",
                            operator, b.deviceId(), e.getMessage());
                    return Mono.error(ApiException.forbidden(GENERIC_DENY));
                });
    }
}
