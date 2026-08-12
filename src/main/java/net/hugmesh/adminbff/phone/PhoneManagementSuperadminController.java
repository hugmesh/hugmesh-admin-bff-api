package net.hugmesh.adminbff.phone;

import io.swagger.v3.oas.annotations.Operation;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;
import net.hugmesh.adminbff.web.dto.PhoneLockRequest;
import net.hugmesh.adminbff.web.dto.PhoneManagementModeRequest;
import net.hugmesh.adminbff.web.dto.PhoneOwnerRequest;
import net.hugmesh.authcore.casdoor.MfaStepUpService;
import net.hugmesh.authcore.config.SessionCookieWebFilter;
import net.hugmesh.commons.security.DomainRegistry;
import net.hugmesh.commons.security.PrincipalDomain;
import net.hugmesh.commons.web.ApiException;

/**
 * The SUPERADMIN WRITE side of the MDM phone registry — the management + lockout mutations
 * over the {@code phone_device} rows the ingest channel writes and {@link
 * PhoneFleetSuperadminController} reads. SECURITY-CRITICAL: this is the ONLY path that writes
 * the AUTHORITATIVE {@code management_mode}, and the reversible device lockout.
 *
 * <h3>Authorization (defence-in-depth + step-up)</h3>
 * The coarse path gate on {@code /bff/superadmin/**} ({@code SecurityConfig.commonRoutes}) is
 * {@code hasRole('SUPERADMIN')}; EVERY mutation here ALSO carries
 * {@code @PreAuthorize("hasRole('SUPERADMIN')")} (an ADMIN is 403 and never reaches the
 * service) AND requires a valid {@code X-PhoneLock-StepUp} token (or a fresh Casdoor-MFA
 * stamp) — the same posture as SSH key-issuance. Like the read controller this is
 * superadmin-only and NOT per-domain scoped (a phone's {@code attachedDomain} is telemetry,
 * not a tenancy wall); the {@link PrincipalDomain} is resolved for audit attribution.
 *
 * <ul>
 *   <li>{@code PUT  /{deviceId}/management} — set managed({@code mesh_owned})/BYOD({@code unmanaged}).</li>
 *   <li>{@code PUT  /{deviceId}/owner} — assign the OPERATOR-AUTHORITATIVE fleet owner
 *       (physical_owner + owner_domain, changeset 305) — the SOLE tenancy wall for the public
 *       {@code /bff/admin/phone-fleet/**} FLEET_ADMIN surface. Provisioning-only (SUPERADMIN);
 *       a fleet-admin can never set its own owner.</li>
 *   <li>{@code POST /{deviceId}/lock} — lock a MANAGED device (409 if BYOD).</li>
 *   <li>{@code POST /{deviceId}/unlock} — unlock a device.</li>
 * </ul>
 * Each returns the updated {@link PhoneDevice}; an unknown device id is a clean 404.
 */
@RestController
@RequestMapping("/bff/superadmin/phone-devices")
@Validated
public class PhoneManagementSuperadminController {

    private static final Logger log = LoggerFactory.getLogger(PhoneManagementSuperadminController.class);
    private static final int MAX_DEVICE_ID = 128;

    private final PhoneManagementService service;
    private final PhoneLockStepUpGate stepUp;
    private final MfaStepUpService mfaStepUp;
    private final DomainRegistry domainRegistry;

    public PhoneManagementSuperadminController(PhoneManagementService service,
                                               PhoneLockStepUpGate stepUp,
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

    private static String actor(Authentication auth) {
        return auth == null ? null : auth.getName();
    }

    // ── set management_mode (SUPERADMIN + step-up) ───────────────────────────────
    @PreAuthorize("hasRole('SUPERADMIN')")
    @Operation(summary = "Set phone management mode", operationId = "phoneManagementSetMode")
    @PutMapping("/{deviceId}/management")
    public Mono<PhoneDevice> setManagement(
            @PathVariable @NotBlank @Size(max = MAX_DEVICE_ID) String deviceId,
            @Valid @RequestBody PhoneManagementModeRequest body,
            @RequestHeader(value = PhoneLockStepUpGate.STEP_UP_HEADER, required = false) String stepUpToken,
            @CookieValue(name = SessionCookieWebFilter.SESSION_COOKIE, required = false) String sessionCookie,
            @RequestHeader(name = HttpHeaders.AUTHORIZATION, required = false) String authHeader,
            Authentication auth) {
        return withStepUp(auth, stepUpToken, sessionCookie, authHeader, "management",
                actor -> service.setManagementMode(deviceId, body.mode(), actor));
    }

    // ── assign the fleet owner (SUPERADMIN + step-up; changeset 305) ─────────────
    @PreAuthorize("hasRole('SUPERADMIN')")
    @Operation(summary = "Assign phone owner", operationId = "phoneManagementSetOwner")
    @PutMapping("/{deviceId}/owner")
    public Mono<PhoneDevice> setOwner(
            @PathVariable @NotBlank @Size(max = MAX_DEVICE_ID) String deviceId,
            @Valid @RequestBody PhoneOwnerRequest body,
            @RequestHeader(value = PhoneLockStepUpGate.STEP_UP_HEADER, required = false) String stepUpToken,
            @CookieValue(name = SessionCookieWebFilter.SESSION_COOKIE, required = false) String sessionCookie,
            @RequestHeader(name = HttpHeaders.AUTHORIZATION, required = false) String authHeader,
            Authentication auth) {
        return withStepUp(auth, stepUpToken, sessionCookie, authHeader, "owner",
                actor -> service.setOwner(deviceId, body.physicalOwner(), body.ownerDomain(), actor));
    }

    // ── lock a MANAGED device (SUPERADMIN + step-up; 409 if BYOD) ────────────────
    @PreAuthorize("hasRole('SUPERADMIN')")
    @Operation(summary = "Lock phone", operationId = "phoneManagementLock")
    @PostMapping("/{deviceId}/lock")
    public Mono<PhoneDevice> lock(
            @PathVariable @NotBlank @Size(max = MAX_DEVICE_ID) String deviceId,
            @Valid @RequestBody(required = false) PhoneLockRequest body,
            @RequestHeader(value = PhoneLockStepUpGate.STEP_UP_HEADER, required = false) String stepUpToken,
            @CookieValue(name = SessionCookieWebFilter.SESSION_COOKIE, required = false) String sessionCookie,
            @RequestHeader(name = HttpHeaders.AUTHORIZATION, required = false) String authHeader,
            Authentication auth) {
        String reason = body == null ? null : body.reason();
        return withStepUp(auth, stepUpToken, sessionCookie, authHeader, "lock",
                actor -> service.lock(deviceId, reason, actor));
    }

    // ── unlock a device (SUPERADMIN + step-up) ───────────────────────────────────
    @PreAuthorize("hasRole('SUPERADMIN')")
    @Operation(summary = "Unlock phone", operationId = "phoneManagementUnlock")
    @PostMapping("/{deviceId}/unlock")
    public Mono<PhoneDevice> unlock(
            @PathVariable @NotBlank @Size(max = MAX_DEVICE_ID) String deviceId,
            @RequestHeader(value = PhoneLockStepUpGate.STEP_UP_HEADER, required = false) String stepUpToken,
            @CookieValue(name = SessionCookieWebFilter.SESSION_COOKIE, required = false) String sessionCookie,
            @RequestHeader(name = HttpHeaders.AUTHORIZATION, required = false) String authHeader,
            Authentication auth) {
        return withStepUp(auth, stepUpToken, sessionCookie, authHeader, "unlock",
                actor -> service.unlock(deviceId, actor));
    }

    /**
     * The shared gate for all three mutations: resolve the actor (401 if none), require step-up
     * (the {@code X-PhoneLock-StepUp} workload token OR a fresh Casdoor-MFA stamp — 403 on
     * missing/invalid), consume the MFA stamp single-use, then run the mutation. Mirrors the SSH
     * key-issuance controller. The SUPERADMIN role floor runs BEFORE the body via
     * {@code @PreAuthorize}, so an ADMIN never reaches here.
     */
    private Mono<PhoneDevice> withStepUp(Authentication auth, String stepUpToken, String sessionCookie,
                                         String authHeader, String verb,
                                         java.util.function.Function<String, Mono<PhoneDevice>> op) {
        String actor = actor(auth);
        if (actor == null || actor.isBlank()) {
            return Mono.error(ApiException.unauthorized("no subject on token"));
        }
        PrincipalDomain scope = scope(auth);
        String sessionToken = SessionCookieWebFilter.bffTokenFrom(sessionCookie, authHeader);
        // UNIFIED step-up: the workload step-up token OR a FRESH Casdoor-MFA stamp (co-equal,
        // flag-gated + fail-closed). Check step-up, consume the MFA stamp single-use, then mutate.
        return mfaStepUp.isFresh(sessionToken)
                .flatMap(mfaFresh -> {
                    if (!stepUp.isSatisfied(actor, stepUpToken, mfaFresh)) {
                        return Mono.error(ApiException.forbidden(
                                verb + " requires step-up re-authentication (present "
                                + PhoneLockStepUpGate.STEP_UP_HEADER + ")"));
                    }
                    log.info("[phone-mgmt] {} by {} (home={})", verb, actor, scope.domain());
                    Mono<Void> consume = mfaFresh ? mfaStepUp.consume(sessionToken) : Mono.empty();
                    return consume.then(op.apply(actor));
                });
    }
}
