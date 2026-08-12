package net.hugmesh.adminbff.desktop;

import io.swagger.v3.oas.annotations.Operation;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;
import net.hugmesh.adminbff.desktop.terminal.DeviceTerminalProperties;
import net.hugmesh.commons.web.ApiException;
import net.hugmesh.adminbff.web.dto.DesktopTerminalStepUpResponse;
import net.hugmesh.adminbff.workload.WorkloadStepUpService;

/**
 * The ADMIN-reachable DESKTOP STEP-UP mint at {@code POST /bff/admin/desktop/step-up} — the
 * gate-4 unblocker for the device-facing privileged desktop paths (in-UI SSH terminal +
 * remote-install). Both of those gate on a valid step-up token; the live
 * {@code DeviceSshTerminalWebSocketHandler} gate-4 accepts an ADMIN, but the ONLY existing mint
 * was {@code POST /bff/superadmin/workload/step-up} ({@code hasRole('SUPERADMIN')}) — so an ADMIN
 * could never satisfy it. This endpoint mints for ADMIN+SUPERADMIN.
 *
 * <h3>Authorization (defence-in-depth + reach control)</h3>
 * Under the coarse {@code /bff/admin/**} gate ({@code hasAnyRole('ADMIN','SUPERADMIN')}). The mint
 * itself is the UNCHANGED {@link WorkloadStepUpService#mint}: it requires THIS replica be the Lease
 * leader AND that the operator holds an ACTIVE device-OR-domain ssh-license (the same
 * {@code device_ssh_license} reach control that gates real SSH) — so an unlicensed admin (or a
 * cross-domain admin with no own-domain license) CANNOT mint, and a non-leader replica refuses. The
 * operator/subject is the JWT subject ({@code never a body field}). The minted token is opaque,
 * per-subject, single-use, 5-min TTL, leader-pinned, constant-time validated. The SUPERADMIN
 * workload mint is left UNTOUCHED (no widening there).
 *
 * <h3>Ships dark</h3>
 * No new flag. The mint 503s while {@code app.device-terminal.enabled=false} (the default) to keep
 * the whole privileged leg dark until launch — an issued token would only ever unlock surfaces that
 * are themselves behind {@code app.device-terminal.enabled} / {@code app.desktop.remote-install.enabled}
 * (both default false), so minting while dark is inert; 503ing makes the dark posture explicit and
 * testable. The role + license authorization runs REGARDLESS (the mint precondition is exercised
 * even while dark via the test that drops the flag-gate).
 */
@RestController
@RequestMapping("/bff/admin/desktop/step-up")
@Validated
public class DesktopStepUpController {

    private static final Logger log = LoggerFactory.getLogger(DesktopStepUpController.class);

    private final WorkloadStepUpService stepUp;
    private final DeviceTerminalProperties terminalProps;

    public DesktopStepUpController(WorkloadStepUpService stepUp,
                                   DeviceTerminalProperties terminalProps) {
        this.stepUp = stepUp;
        this.terminalProps = terminalProps;
    }

    private static String subject(Authentication auth) {
        if (auth != null && auth.getPrincipal() instanceof Jwt jwt) {
            return jwt.getSubject();
        }
        return auth == null ? null : auth.getName();
    }

    /**
     * Mint a short-TTL desktop step-up token for the calling ADMIN/SUPERADMIN. The operator is the
     * JWT subject; the {@link WorkloadStepUpService#mint} active-ssh-license + leader preconditions
     * apply (an unlicensed/cross-domain-unlicensed admin is denied 403). Returns
     * {@link DesktopTerminalStepUpResponse}. 503 while the device-terminal leg ships dark.
     */
    @PreAuthorize("hasAnyRole('ADMIN','SUPERADMIN')")
    @Operation(summary = "Mint", operationId = "desktopStepUpMint")
    @PostMapping
    public Mono<DesktopTerminalStepUpResponse> mint(Authentication auth) {
        String subject = subject(auth);
        if (subject == null || subject.isBlank()) {
            return Mono.error(ApiException.unauthorized("no subject on token"));
        }
        // Ships dark: keep the privileged leg dark until launch. A token here only unlocks surfaces
        // already behind the device-terminal / remote-install flags, so minting while dark is inert
        // — 503 makes that explicit. The role gate + license precondition below are NOT bypassed in
        // the live (flag-on) path; the authz is proven dark in the test that flips this gate.
        if (!terminalProps.isEnabled()) {
            return Mono.error(ApiException.serviceUnavailable(
                    "desktop step-up ships dark (app.device-terminal.enabled=false) — "
                    + "authorization is live, no token was minted"));
        }
        // operator == subject (never a body field). mint() enforces leader + active ssh-license.
        return stepUp.mint(subject, subject)
                .map(token -> new DesktopTerminalStepUpResponse(
                        token, WorkloadStepUpService.STEP_UP_TTL.toMinutes()))
                .doOnNext(r -> log.info("[desktop-stepup] minted desktop step-up (ttl={}m)",
                        WorkloadStepUpService.STEP_UP_TTL.toMinutes()))
                .onErrorResume(WorkloadStepUpService.StepUpDeniedException.class,
                        e -> Mono.error(ApiException.forbidden(e.getMessage())));
    }
}
