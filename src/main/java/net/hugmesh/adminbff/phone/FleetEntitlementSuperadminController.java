package net.hugmesh.adminbff.phone;

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
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;
import net.hugmesh.adminbff.web.StepUpRequiredException;
import net.hugmesh.adminbff.web.dto.FleetEntitlementRequest;
import net.hugmesh.authcore.casdoor.MfaStepUpService;
import net.hugmesh.authcore.config.SessionCookieWebFilter;
import net.hugmesh.commons.web.ApiException;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * The SUPERADMIN admin surface for the FLEET-ADMIN entitlement gate (changeset 306) — where a
 * superadmin grants/updates/revokes the per-subject subscription that a non-superadmin
 * {@code FLEET_ADMIN} needs to reach the public {@code /bff/admin/phone-fleet/**} owner surface.
 *
 * <h3>Authorization (defence-in-depth + step-up)</h3>
 * The coarse {@code /bff/superadmin/**} gate is {@code hasRole('SUPERADMIN')}; every endpoint
 * ALSO carries {@code @PreAuthorize("hasRole('SUPERADMIN')")}. The two MUTATIONS (PUT upsert /
 * DELETE revoke) additionally require step-up ({@code X-PhoneLock-StepUp} workload token OR a
 * fresh Casdoor-MFA stamp), reusing {@link PhoneLockStepUpGate} — the SAME posture as the phone
 * lockout plane, NOT a new step-up mechanism. The GET list is a read (SUPERADMIN, no step-up),
 * mirroring the read-only {@link PhoneFleetSuperadminController}.
 *
 * <ul>
 *   <li>{@code GET  ""} — list all entitlements.</li>
 *   <li>{@code PUT  /{subject}} — upsert {active?, seats?, expiresAt?} (active defaults true).</li>
 *   <li>{@code DELETE /{subject}} — revoke.</li>
 * </ul>
 */
@RestController
@RequestMapping("/bff/superadmin/fleet-entitlements")
@Validated
public class FleetEntitlementSuperadminController {

    private static final Logger log = LoggerFactory.getLogger(FleetEntitlementSuperadminController.class);
    private static final int MAX_SUBJECT = 400;

    private final FleetEntitlementService service;
    private final PhoneLockStepUpGate stepUp;
    private final MfaStepUpService mfaStepUp;

    public FleetEntitlementSuperadminController(FleetEntitlementService service,
                                                PhoneLockStepUpGate stepUp, MfaStepUpService mfaStepUp) {
        this.service = service;
        this.stepUp = stepUp;
        this.mfaStepUp = mfaStepUp;
    }

    // ── list all entitlements (SUPERADMIN read) ──────────────────────────────────
    @PreAuthorize("hasRole('SUPERADMIN')")
    @Operation(summary = "List fleet entitlements", operationId = "fleetEntitlementList")
    @GetMapping("")
    public Mono<Map<String, Object>> list() {
        return service.list().collectList().map(entitlements -> {
            Map<String, Object> out = new LinkedHashMap<>();
            out.put("entitlements", entitlements);
            return out;
        });
    }

    // ── upsert an entitlement (SUPERADMIN + step-up) ─────────────────────────────
    @PreAuthorize("hasRole('SUPERADMIN')")
    @Operation(summary = "Upsert fleet entitlement", operationId = "fleetEntitlementUpsert")
    @PutMapping("/{subject}")
    public Mono<FleetEntitlement> upsert(
            @PathVariable @NotBlank @Size(max = MAX_SUBJECT) String subject,
            @Valid @RequestBody(required = false) FleetEntitlementRequest body,
            @RequestHeader(value = PhoneLockStepUpGate.STEP_UP_HEADER, required = false) String stepUpToken,
            @CookieValue(name = SessionCookieWebFilter.SESSION_COOKIE, required = false) String sessionCookie,
            @RequestHeader(name = HttpHeaders.AUTHORIZATION, required = false) String authHeader,
            Authentication auth) {
        FleetEntitlementRequest b = body == null
                ? new FleetEntitlementRequest(null, null, null) : body;
        return withStepUp(auth, stepUpToken, sessionCookie, authHeader, "entitlement upsert",
                actor -> service.upsert(subject, b.activeOrDefault(), b.seats(), b.expiresAt()));
    }

    // ── revoke an entitlement (SUPERADMIN + step-up) ─────────────────────────────
    @PreAuthorize("hasRole('SUPERADMIN')")
    @Operation(summary = "Delete fleet entitlement", operationId = "fleetEntitlementDelete")
    @DeleteMapping("/{subject}")
    public Mono<ResponseEntity<Map<String, Object>>> delete(
            @PathVariable @NotBlank @Size(max = MAX_SUBJECT) String subject,
            @RequestHeader(value = PhoneLockStepUpGate.STEP_UP_HEADER, required = false) String stepUpToken,
            @CookieValue(name = SessionCookieWebFilter.SESSION_COOKIE, required = false) String sessionCookie,
            @RequestHeader(name = HttpHeaders.AUTHORIZATION, required = false) String authHeader,
            Authentication auth) {
        return withStepUp(auth, stepUpToken, sessionCookie, authHeader, "entitlement delete",
                actor -> service.delete(subject).map(n -> ResponseEntity.ok(Map.of("deleted", n))));
    }

    /**
     * The shared step-up gate for the two mutations (mirrors the phone-lockout plane): resolve
     * the actor (401 if none), require step-up (workload token OR fresh Casdoor-MFA stamp — 403
     * otherwise), consume the MFA stamp single-use, then run the mutation. The SUPERADMIN role
     * floor runs BEFORE the body via {@code @PreAuthorize}.
     */
    private <T> Mono<T> withStepUp(Authentication auth, String stepUpToken, String sessionCookie,
                                   String authHeader, String verb,
                                   java.util.function.Function<String, Mono<T>> op) {
        String actor = auth == null ? null : auth.getName();
        if (actor == null || actor.isBlank()) {
            return Mono.error(ApiException.unauthorized("no subject on token"));
        }
        String sessionToken = SessionCookieWebFilter.bffTokenFrom(sessionCookie, authHeader);
        return mfaStepUp.isFresh(sessionToken)
                .flatMap(mfaFresh -> {
                    if (!stepUp.isSatisfied(actor, stepUpToken, mfaFresh)) {
                        return Mono.error(StepUpRequiredException.forRetryHeader(
                                PhoneLockStepUpGate.STEP_UP_HEADER, verb));
                    }
                    log.info("[fleet-entitlement] {} by {}", verb, actor);
                    Mono<Void> consume = mfaFresh ? mfaStepUp.consume(sessionToken) : Mono.empty();
                    return consume.then(op.apply(actor));
                });
    }
}
