package net.hugmesh.adminbff.servicecatalog;

import net.hugmesh.adminbff.mfa.PrincipalSessionToken;
import io.swagger.v3.oas.annotations.Operation;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import org.springframework.http.HttpHeaders;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import net.hugmesh.authcore.casdoor.MfaStepUpService;
import net.hugmesh.authcore.config.SessionCookieWebFilter;
import net.hugmesh.commons.web.ApiException;
import net.hugmesh.adminbff.web.StepUpRequiredException;
import net.hugmesh.adminbff.web.dto.ServiceCurationRequest;

/**
 * The SUPERADMIN App-Store CURATION console — superadmin CRUD over the per-domain offered
 * catalog ({@code service_curation}, schema 100). The TOP tier of the two-tier curation:
 * the cross-domain infra superadmin OFFERS / WITHDRAWS a {@code service_key} FOR a specific
 * {@code domain}; a brand admin only READS their own domain's offered set (the bottom tier,
 * {@code AdminServiceStoreController}).
 *
 * <h3>Authorization — SUPERADMIN-ONLY (defence-in-depth)</h3>
 * Mounted under {@code /bff/superadmin/**}, whose coarse gate in
 * {@link net.hugmesh.adminbff.config.SecurityConfig} is {@code hasRole('SUPERADMIN')}
 * (admin/mod/user never clear it). EVERY method ALSO carries
 * {@code @PreAuthorize("hasRole('SUPERADMIN')")} — so:
 * <ul>
 *   <li>SUPERADMIN — ALLOWED (manages ALL domains; the {@code domain} is the explicit PATH
 *       target, never a body field).</li>
 *   <li>ADMIN / MOD / USER — 403 (walled at the coarse {@code /bff/superadmin/**} gate AND
 *       the per-method SUPERADMIN gate).</li>
 * </ul>
 * {@code curated_by_subject} is stamped from the SUPERADMIN's {@code jwt.getSubject()}.
 *
 * <h3>Step-up on {@link #offer} ONLY</h3>
 * ON TOP of the role gate, {@link #offer} requires a valid {@code X-ServiceStore-StepUp} token
 * ({@link ServiceStoreStepUpGate}, A5-unified with a fresh Casdoor-MFA stamp) — the same posture
 * {@link ServiceStoreWizardController}'s scaffold/federate writes take. {@code list} is a read and
 * stays role-only.
 *
 * <p><b>{@code withdraw} is ROLE-ONLY, by the operator's decision.</b> It was gated alongside
 * {@code offer} when hugmesh-admin-bff-api #51 landed, over the objection recorded in the
 * superadmin-service-catalog-ui #4 plan ("gating it means a step-up to REMOVE a service from a
 * domain, which may be the wrong friction"). The question was put to the operator on
 * hugmesh-generator #347 (decision 6) and answered <b>"role-only — remove the gate"</b> on
 * 2026-09-10, so the gate is gone:
 * {@code @PreAuthorize("hasRole('SUPERADMIN')")} plus the coarse {@code /bff/superadmin/**} gate
 * is the whole protection on this verb, and it takes no step-up header, session cookie or
 * {@code Authorization} parameter at all.
 *
 * <p>The UI needs nothing for this. hugmesh-superadmin-service-catalog-ui PR #11 only ever
 * REACTS to a "requires step-up" 403 ({@code service-catalog-curation.component.ts act()}); with
 * no such denial the withdraw call takes the ordinary success path, and its generated client
 * ({@code fn/service-curation-controller/service-curation-withdraw.ts}) never declared the header
 * in the first place — the token rides an {@code HttpContext} + interceptor seam. A previously
 * confirmed token is simply ignored on the wire here.
 */
@RestController
@RequestMapping("/bff/superadmin/service-store")
@Validated
public class ServiceCurationController {

    private final ServiceCurationService service;
    private final ServiceStoreStepUpGate stepUp;
    private final MfaStepUpService mfaStepUp;

    public ServiceCurationController(ServiceCurationService service,
                                     ServiceStoreStepUpGate stepUp,
                                     MfaStepUpService mfaStepUp) {
        this.service = service;
        this.stepUp = stepUp;
        this.mfaStepUp = mfaStepUp;
    }

    /** The Casdoor subject of the acting SUPERADMIN, from the validated JWT. */
    private static String subject(Authentication auth) {
        if (auth != null && auth.getPrincipal() instanceof Jwt jwt) {
            return jwt.getSubject();
        }
        return auth == null ? null : auth.getName();
    }

    // ── List the per-domain catalog (offered + withdrawn) for a {domain} (SUPERADMIN) ──
    @PreAuthorize("hasRole('SUPERADMIN')")
    @Operation(summary = "List", operationId = "serviceCurationList")
    @GetMapping("/{domain}")
    public Flux<ServiceCuration> list(
            @PathVariable @NotBlank @Size(max = 253) String domain) {
        return service.listForDomain(domain);
    }

    // ── Offer a service_key to a {domain}'s admins (SUPERADMIN; step-up) ─────────
    @PreAuthorize("hasRole('SUPERADMIN')")
    @Operation(summary = "Offer", operationId = "serviceCurationOffer")
    @PostMapping("/{domain}/offer")
    public Mono<ServiceCuration> offer(
            @PathVariable @NotBlank @Size(max = 253) String domain,
            @Valid @RequestBody ServiceCurationRequest body,
            @RequestHeader(value = ServiceStoreStepUpGate.STEP_UP_HEADER, required = false) String stepUpToken,
            @CookieValue(name = SessionCookieWebFilter.SESSION_COOKIE, required = false) String sessionCookie,
            @RequestHeader(name = HttpHeaders.AUTHORIZATION, required = false) String authHeader,
            Authentication auth) {
        String actor = subject(auth);
        if (actor == null || actor.isBlank()) {
            return Mono.error(ApiException.unauthorized("no subject on token"));
        }
        String sessionToken = PrincipalSessionToken.of(sessionCookie, authHeader);
        return mfaStepUp.isFresh(sessionToken)
                .flatMap(mfaFresh -> offerIfStepUpSatisfied(mfaFresh, actor, stepUpToken, sessionToken,
                        domain, body));
    }

    private Mono<ServiceCuration> offerIfStepUpSatisfied(boolean mfaFresh, String actor,
            String stepUpToken, String sessionToken, String domain, ServiceCurationRequest body) {
        if (!stepUp.isSatisfied(actor, stepUpToken, mfaFresh)) {
            return Mono.error(StepUpRequiredException.forRetryHeader(
                    ServiceStoreStepUpGate.STEP_UP_HEADER, "offering a service"));
        }
        Mono<Void> consume = mfaFresh ? mfaStepUp.consume(sessionToken) : Mono.empty();
        return consume.then(service.offer(domain, body.serviceKey(), actor));
    }

    // ── Withdraw a service_key from a {domain}'s offered catalog (SUPERADMIN; ROLE-ONLY) ──
    // No step-up: operator answer "role-only — remove the gate" (hugmesh-generator #347
    // decision 6, 2026-09-10). The
    // signature deliberately carries no step-up header / cookie / Authorization parameter, so the
    // dumped openapi contract shows this verb as role-protected rather than merely lenient.
    @PreAuthorize("hasRole('SUPERADMIN')")
    @Operation(summary = "Withdraw", operationId = "serviceCurationWithdraw")
    @PostMapping("/{domain}/withdraw")
    public Mono<ServiceCuration> withdraw(
            @PathVariable @NotBlank @Size(max = 253) String domain,
            @Valid @RequestBody ServiceCurationRequest body,
            Authentication auth) {
        String actor = subject(auth);
        if (actor == null || actor.isBlank()) {
            return Mono.error(ApiException.unauthorized("no subject on token"));
        }
        return service.withdraw(domain, body.serviceKey(), actor);
    }
}
