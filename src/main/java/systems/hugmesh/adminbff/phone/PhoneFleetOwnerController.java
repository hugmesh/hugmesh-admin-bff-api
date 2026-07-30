package systems.hugmesh.adminbff.phone;

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
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;
import systems.hugmesh.adminbff.web.dto.PhoneLockRequest;
import systems.hugmesh.authcore.casdoor.MfaStepUpService;
import systems.hugmesh.authcore.config.SessionCookieWebFilter;
import systems.hugmesh.commons.security.DomainRegistry;
import systems.hugmesh.commons.security.PrincipalDomain;
import systems.hugmesh.commons.security.Roles;
import systems.hugmesh.commons.web.ApiException;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * The FLEET-OWNER surface — the PUBLIC fe-gateway {@code /bff/admin/phone-fleet/**} path where a
 * non-superadmin {@code FLEET_ADMIN} (or {@code ADMIN}) manages ONLY THEIR OWN phones. This is
 * the ONE phone controller reachable off the public gateway by a non-superadmin, so its tenancy
 * wall is SECURITY-CRITICAL and MUST be airtight + fail-closed.
 *
 * <h3>The tenancy wall (the SOLE boundary — no tailnet defence-in-depth)</h3>
 * Unlike the {@code /bff/superadmin/**} lock endpoints (which sit behind the in-cluster mTLS
 * transport too), this surface is public, so the owner+domain predicate is the ONLY thing
 * standing between two fleet owners. For a non-superadmin caller EVERY read and mutation is
 * predicated {@code WHERE physical_owner = caller-subject AND owner_domain = caller-domain}
 * (changeset 305 columns; BOTH, resolved from the validated JWT — {@code auth.getName()} +
 * {@link PrincipalDomain}). A caller can therefore never see or lock another owner's device, nor
 * a device in another domain, nor an unassigned device (a NULL owner never matches). A cross-owner
 * / cross-domain / unknown device is a uniform 404 (no enumeration — a 403 would leak existence).
 *
 * <h3>Entitlement gate</h3>
 * A non-superadmin ALSO needs an ACTIVE, unexpired {@link FleetEntitlementService} row for their
 * subject, else every endpoint is a 403 "fleet entitlement required".
 *
 * <h3>Superadmin</h3>
 * A genuine {@code ROLE_SUPERADMIN} AUTHORITY (never an empty/absent scope) is UNSCOPED (sees the
 * whole fleet) AND entitlement-EXEMPT — superadmins keep the richer {@code /bff/superadmin}
 * surface too. The bypass keys on the authority, so a scope that fails to resolve can never be
 * mistaken for a superadmin.
 *
 * <h3>What a fleet-admin CANNOT do</h3>
 * Mark-managed and owner-assignment are PROVISIONING (SUPERADMIN-only, on the
 * {@code /bff/superadmin/phone-devices} surface). This controller exposes only read + lock/unlock
 * of ALREADY-owned, ALREADY-managed devices; lock/unlock require step-up
 * ({@code X-PhoneLock-StepUp}) exactly like the superadmin plane.
 */
@RestController
@RequestMapping("/bff/admin/phone-fleet")
@Validated
public class PhoneFleetOwnerController {

    private static final Logger log = LoggerFactory.getLogger(PhoneFleetOwnerController.class);
    private static final int MAX_DEVICE_ID = 128;

    private final PhoneDeviceService phones;
    private final PhoneManagementService management;
    private final FleetEntitlementService entitlements;
    private final PhoneLockStepUpGate stepUp;
    private final MfaStepUpService mfaStepUp;
    private final DomainRegistry domainRegistry;

    public PhoneFleetOwnerController(PhoneDeviceService phones, PhoneManagementService management,
                                     FleetEntitlementService entitlements, PhoneLockStepUpGate stepUp,
                                     MfaStepUpService mfaStepUp, DomainRegistry domainRegistry) {
        this.phones = phones;
        this.management = management;
        this.entitlements = entitlements;
        this.stepUp = stepUp;
        this.mfaStepUp = mfaStepUp;
        this.domainRegistry = domainRegistry;
    }

    // ── list own+domain fleet (SUPERADMIN unscoped) ──────────────────────────────
    @PreAuthorize("hasAnyRole('FLEET_ADMIN','ADMIN','SUPERADMIN')")
    @Operation(summary = "List my phone fleet", operationId = "phoneFleetOwnerList")
    @GetMapping("")
    public Mono<Map<String, Object>> list(Authentication auth) {
        if (isSuperadmin(auth)) {
            return phones.list().collectList().map(PhoneFleetOwnerController::envelope);
        }
        return entitledScope(auth).flatMap(s ->
                phones.listOwned(s.subject(), s.domain()).collectList()
                        .map(PhoneFleetOwnerController::envelope));
    }

    // ── one owned device by id; 404 (not 403) when not owned-in-domain ───────────
    @PreAuthorize("hasAnyRole('FLEET_ADMIN','ADMIN','SUPERADMIN')")
    @Operation(summary = "Get my phone", operationId = "phoneFleetOwnerGet")
    @GetMapping("/{deviceId}")
    public Mono<PhoneDevice> get(@PathVariable @NotBlank @Size(max = MAX_DEVICE_ID) String deviceId,
                                 Authentication auth) {
        if (isSuperadmin(auth)) {
            return phones.find(deviceId).switchIfEmpty(notFound(deviceId));
        }
        return entitledScope(auth).flatMap(s ->
                phones.findOwned(deviceId, s.subject(), s.domain()).switchIfEmpty(notFound(deviceId)));
    }

    // ── lock an owned, managed device (step-up; 404 if not owned, 409 if BYOD) ───
    @PreAuthorize("hasAnyRole('FLEET_ADMIN','ADMIN','SUPERADMIN')")
    @Operation(summary = "Lock my phone", operationId = "phoneFleetOwnerLock")
    @PostMapping("/{deviceId}/lock")
    public Mono<PhoneDevice> lock(
            @PathVariable @NotBlank @Size(max = MAX_DEVICE_ID) String deviceId,
            @Valid @RequestBody(required = false) PhoneLockRequest body,
            @RequestHeader(value = PhoneLockStepUpGate.STEP_UP_HEADER, required = false) String stepUpToken,
            @CookieValue(name = SessionCookieWebFilter.SESSION_COOKIE, required = false) String sessionCookie,
            @RequestHeader(name = HttpHeaders.AUTHORIZATION, required = false) String authHeader,
            Authentication auth) {
        String reason = body == null ? null : body.reason();
        return withStepUp(auth, stepUpToken, sessionCookie, authHeader, "lock", actor -> {
            if (isSuperadmin(auth)) {
                return management.lock(deviceId, reason, actor);
            }
            return entitledScope(auth).flatMap(s ->
                    management.lockOwned(deviceId, reason, actor, s.subject(), s.domain()));
        });
    }

    // ── unlock an owned device (step-up; 404 if not owned) ───────────────────────
    @PreAuthorize("hasAnyRole('FLEET_ADMIN','ADMIN','SUPERADMIN')")
    @Operation(summary = "Unlock my phone", operationId = "phoneFleetOwnerUnlock")
    @PostMapping("/{deviceId}/unlock")
    public Mono<PhoneDevice> unlock(
            @PathVariable @NotBlank @Size(max = MAX_DEVICE_ID) String deviceId,
            @RequestHeader(value = PhoneLockStepUpGate.STEP_UP_HEADER, required = false) String stepUpToken,
            @CookieValue(name = SessionCookieWebFilter.SESSION_COOKIE, required = false) String sessionCookie,
            @RequestHeader(name = HttpHeaders.AUTHORIZATION, required = false) String authHeader,
            Authentication auth) {
        return withStepUp(auth, stepUpToken, sessionCookie, authHeader, "unlock", actor -> {
            if (isSuperadmin(auth)) {
                return management.unlock(deviceId, actor);
            }
            return entitledScope(auth).flatMap(s ->
                    management.unlockOwned(deviceId, actor, s.subject(), s.domain()));
        });
    }

    // ── scope resolution + gates ─────────────────────────────────────────────────

    /** A genuine ROLE_SUPERADMIN AUTHORITY (never an empty/unresolved scope) — the ONLY
     *  unscoped + entitlement-exempt bypass. Keyed on the authority so a scope that fails to
     *  resolve can never be mistaken for a superadmin. */
    private static boolean isSuperadmin(Authentication auth) {
        return auth != null && Roles.isSuperadmin(auth.getAuthorities());
    }

    /**
     * Resolve the caller's owner scope (subject + domain) and enforce the entitlement gate —
     * the whole non-superadmin admission check. FAIL-CLOSED: a blank subject or an unresolved
     * domain ({@link PrincipalDomain#NO_DOMAIN} / blank) is a 403 (never an unscoped read by
     * accident); a resolvable identity WITHOUT an active entitlement is a 403 "fleet entitlement
     * required". Only a fully-resolved, entitled caller emits an {@link OwnerScope}.
     */
    private Mono<OwnerScope> entitledScope(Authentication auth) {
        String subject = auth == null ? null : auth.getName();
        String domain = PrincipalDomain.of(auth, domainRegistry).domain();
        if (subject == null || subject.isBlank() || domain == null || domain.isBlank()
                || PrincipalDomain.NO_DOMAIN.equals(domain)) {
            return Mono.error(ApiException.forbidden(
                    "fleet access requires a resolvable owner identity and domain"));
        }
        return entitlements.isEntitled(subject).flatMap(ok -> ok
                ? Mono.just(new OwnerScope(subject, domain))
                : Mono.error(ApiException.forbidden("fleet entitlement required")));
    }

    /**
     * The shared step-up gate for the two mutations (mirrors the superadmin plane): resolve the
     * actor (401 if none), require step-up (the {@code X-PhoneLock-StepUp} workload token OR a
     * fresh Casdoor-MFA stamp — 403 otherwise), consume the MFA stamp single-use, then run the
     * mutation. The role floor runs BEFORE the body via {@code @PreAuthorize}.
     */
    private Mono<PhoneDevice> withStepUp(Authentication auth, String stepUpToken, String sessionCookie,
                                         String authHeader, String verb,
                                         java.util.function.Function<String, Mono<PhoneDevice>> op) {
        String actor = auth == null ? null : auth.getName();
        if (actor == null || actor.isBlank()) {
            return Mono.error(ApiException.unauthorized("no subject on token"));
        }
        String sessionToken = SessionCookieWebFilter.bffTokenFrom(sessionCookie, authHeader);
        return mfaStepUp.isFresh(sessionToken)
                .flatMap(mfaFresh -> {
                    if (!stepUp.isSatisfied(actor, stepUpToken, mfaFresh)) {
                        return Mono.error(ApiException.forbidden(
                                verb + " requires step-up re-authentication (present "
                                + PhoneLockStepUpGate.STEP_UP_HEADER + ")"));
                    }
                    log.info("[phone-fleet] {} by {}", verb, actor);
                    Mono<Void> consume = mfaFresh ? mfaStepUp.consume(sessionToken) : Mono.empty();
                    return consume.then(op.apply(actor));
                });
    }

    private static Mono<PhoneDevice> notFound(String deviceId) {
        return Mono.error(ApiException.notFound("phone '" + deviceId + "' not found"));
    }

    private static Map<String, Object> envelope(java.util.List<PhoneDevice> phones) {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("phones", phones);
        return out;
    }

    /** The caller's resolved, entitled owner scope — subject AND domain (both load-bearing). */
    private record OwnerScope(String subject, String domain) {
    }
}
