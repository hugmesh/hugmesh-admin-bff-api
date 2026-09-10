package net.hugmesh.adminbff.servicecatalog;

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
 * <h3>Step-up on the MUTATING verbs</h3>
 * ON TOP of the role gate, {@link #offer} and {@link #withdraw} require a valid
 * {@code X-ServiceStore-StepUp} token ({@link ServiceStoreStepUpGate}, A5-unified with a fresh
 * Casdoor-MFA stamp) — the same posture {@link ServiceStoreWizardController}'s scaffold/federate
 * writes take. {@code list} is a read and stays role-only.
 *
 * <p><b>Why {@code withdraw} is gated too.</b> It is the reversible half, and the
 * superadmin-service-catalog-ui #4 plan recommended leaving it role-only ("gating it means a
 * step-up to REMOVE a service from a domain, which may be the wrong friction"). That is recorded
 * as the operator's open call. It is gated here because the issue of record scopes all three verbs
 * (hugmesh-admin-bff-api #51, and the 2026-09-02 comment on catalog-ui #4), so NOT gating it would
 * be the scope change — and withdrawing a service from a live domain is an availability event for
 * that brand's users. The UI already speaks step-up on withdraw either way, so reverting to
 * role-only is this one {@code @RequestHeader}/gate block plus the openapi re-dump.
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
        String sessionToken = SessionCookieWebFilter.bffTokenFrom(sessionCookie, authHeader);
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

    // ── Withdraw a service_key from a {domain}'s offered catalog (SUPERADMIN; step-up) ──
    @PreAuthorize("hasRole('SUPERADMIN')")
    @Operation(summary = "Withdraw", operationId = "serviceCurationWithdraw")
    @PostMapping("/{domain}/withdraw")
    public Mono<ServiceCuration> withdraw(
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
        String sessionToken = SessionCookieWebFilter.bffTokenFrom(sessionCookie, authHeader);
        return mfaStepUp.isFresh(sessionToken)
                .flatMap(mfaFresh -> withdrawIfStepUpSatisfied(mfaFresh, actor, stepUpToken, sessionToken,
                        domain, body));
    }

    private Mono<ServiceCuration> withdrawIfStepUpSatisfied(boolean mfaFresh, String actor,
            String stepUpToken, String sessionToken, String domain, ServiceCurationRequest body) {
        if (!stepUp.isSatisfied(actor, stepUpToken, mfaFresh)) {
            return Mono.error(StepUpRequiredException.forRetryHeader(
                    ServiceStoreStepUpGate.STEP_UP_HEADER, "withdrawing a service"));
        }
        Mono<Void> consume = mfaFresh ? mfaStepUp.consume(sessionToken) : Mono.empty();
        return consume.then(service.withdraw(domain, body.serviceKey(), actor));
    }
}
