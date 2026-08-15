package net.hugmesh.adminbff.backingservices;

import io.swagger.v3.oas.annotations.Operation;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;
import net.hugmesh.authcore.casdoor.MfaStepUpService;
import net.hugmesh.authcore.config.SessionCookieWebFilter;
import net.hugmesh.commons.web.ApiException;
import net.hugmesh.adminbff.web.StepUpRequiredException;
import net.hugmesh.adminbff.web.dto.SetBackingServiceModeRequest;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * SUPERADMIN MANAGED BACKING-SERVICES admin plane (reactive WebFlux; ships dark) at
 * {@code /bff/superadmin/backing-services} — the admin web-UI half of the managed/self-hosted
 * axis (cloud-deploy DESIGN I8-DESIGN, Lane M3), cloning the {@link
 * net.hugmesh.adminbff.golive.GoLiveController} posture EXACTLY.
 *
 * <h3>INTENT ONLY — the pinned contract</h3>
 * The live flip (prune the in-mesh workload + re-point the consumers' endpoints at a managed
 * cloud service) is a build-time act (the generator's {@code gate_backing_services()}) or a
 * future reconciler act. This controller RECORDS the desired MODE INTENT only: a
 * {@code backing_service_mode} row + a transactional-outbox event; the ships-dark
 * {@link BackingServiceModeReconciler} skeleton (logs-only in v1) converges it later.
 *
 * <h3>Authorization (defence-in-depth)</h3>
 * The gateway + {@code SecurityConfig} gate {@code /bff/superadmin/**} to
 * {@code hasRole('SUPERADMIN')} (an ADMIN never reaches the controller). ON TOP of that, EVERY
 * endpoint here adds {@code @PreAuthorize("hasRole('SUPERADMIN')")} (a managed backing-service
 * swap is cross-domain infra, above a brand admin), and the MUTATING verb additionally requires
 * a valid {@code X-BackingServices-StepUp} token ({@link BackingServiceStepUpGate}, A5-unified
 * with a fresh Casdoor-MFA stamp) — the design's "human confirm step".
 *
 * <h3>SHIPS DARK</h3>
 * {@code app.backing-services.enabled=false} by default → the mutating verb returns a 503
 * {@code dark:true} descriptor and writes NOTHING; reads (catalog + current state) stay live so
 * the console renders honestly.
 *
 * <ul>
 *   <li>{@code GET  /bff/superadmin/backing-services} — the closed catalog JOINED with the
 *       current recorded mode per service (+ the enabled flag + the intent-only note).</li>
 *   <li>{@code PUT  /bff/superadmin/backing-services/{id}/mode} — record a self-hosted/managed
 *       mode intent (step-up). Tier-3/docs-only ids are REFUSED (409); dark -> 503; bad
 *       vocabulary -> 400; happy -> the recorded intent (persisted + outbox row in one tx).</li>
 * </ul>
 */
@RestController
@RequestMapping("/bff/superadmin/backing-services")
@Validated
public class BackingServiceController {

    private static final int MAX_ID = 64;

    private final BackingServiceService service;
    private final BackingServiceStepUpGate stepUp;
    private final MfaStepUpService mfaStepUp;

    public BackingServiceController(BackingServiceService service,
                                    BackingServiceStepUpGate stepUp,
                                    MfaStepUpService mfaStepUp) {
        this.service = service;
        this.stepUp = stepUp;
        this.mfaStepUp = mfaStepUp;
    }

    private static String subject(Authentication auth) {
        if (auth != null && auth.getPrincipal() instanceof Jwt jwt) {
            return jwt.getSubject();
        }
        return auth == null ? null : auth.getName();
    }

    // ── catalog + current state (read; live even while dark) ────────────────────────
    @PreAuthorize("hasRole('SUPERADMIN')")
    @Operation(summary = "Backing-services catalog + state", operationId = "backingServicesCatalog")
    @GetMapping
    public Mono<Map<String, Object>> catalog() {
        return service.catalogWithState().map(services -> {
            Map<String, Object> out = new LinkedHashMap<>();
            out.put("enabled", service.isEnabled());
            out.put("services", services);
            // The honesty banner the console renders: recording a mode here never re-points a
            // datastore — the generator/effector leg does, and tier-3 services are docs-only.
            out.put("note", intentNote());
            return out;
        });
    }

    // ── record a mode intent (mutating; step-up; dark -> 503; tier-3 -> 409) ─────────
    @PreAuthorize("hasRole('SUPERADMIN')")
    @Operation(summary = "Set backing-service mode", operationId = "backingServicesSetMode")
    @PutMapping("/{id}/mode")
    public Mono<ResponseEntity<Map<String, Object>>> setMode(
            @PathVariable @NotBlank @Size(max = MAX_ID) String id,
            @Valid @RequestBody SetBackingServiceModeRequest body,
            @RequestHeader(value = BackingServiceStepUpGate.STEP_UP_HEADER, required = false)
            String stepUpToken,
            @CookieValue(name = SessionCookieWebFilter.SESSION_COOKIE, required = false)
            String sessionCookie,
            @RequestHeader(name = HttpHeaders.AUTHORIZATION, required = false) String authHeader,
            Authentication auth) {
        String actor = subject(auth);
        if (actor == null || actor.isBlank()) {
            return Mono.error(ApiException.unauthorized("no subject on token"));
        }
        // The caller's opaque bff_ session (cookie OR synthesised-from-bearer), derived exactly
        // as GoLiveController / ImageBuildController do — NEVER a body field.
        String sessionToken = SessionCookieWebFilter.bffTokenFrom(sessionCookie, authHeader);
        return mfaStepUp.isFresh(sessionToken)
                .flatMap(mfaFresh -> recordIfStepUpSatisfied(mfaFresh, actor, stepUpToken,
                        sessionToken, id, body));
    }

    // ── step-up-gated body (clone of the go-live controller helper) ──────────────────

    /** Validate step-up, consume the MFA single-use, then record — mapping dark -> 503, tier-3
     *  docs-only -> 409, and vocabulary refusals -> 400. */
    private Mono<ResponseEntity<Map<String, Object>>> recordIfStepUpSatisfied(
            boolean mfaFresh, String actor, String stepUpToken, String sessionToken, String id,
            SetBackingServiceModeRequest body) {
        if (!stepUp.isSatisfied(actor, stepUpToken, mfaFresh)) {
            return Mono.error(StepUpRequiredException.forRetryHeader(
                    BackingServiceStepUpGate.STEP_UP_HEADER, "changing a backing-service mode"));
        }
        Mono<Void> consume = mfaFresh ? mfaStepUp.consume(sessionToken) : Mono.empty();
        return consume.then(service.recordMode(actor, id, body)
                .map(intent -> {
                    Map<String, Object> out = new LinkedHashMap<>(intent.toMap());
                    out.put("note", intentNote());
                    return ResponseEntity.ok(out);
                })
                .onErrorResume(BackingServiceService.BackingServiceDarkException.class,
                        e -> Mono.just(darkResponse()))
                .onErrorResume(BackingServiceService.BackingServiceDocsOnlyException.class,
                        e -> Mono.error(ApiException.conflict(e.getMessage())))
                .onErrorResume(BackingServiceService.BackingServiceValidationException.class,
                        e -> Mono.error(ApiException.badRequest(e.getMessage()))));
    }

    /** The 503 descriptor the mutating verb returns while dark — nothing was written. */
    private static ResponseEntity<Map<String, Object>> darkResponse() {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("dark", true);
        body.put("note", "managed backing-services admin ships dark "
                + "(app.backing-services.enabled=false) — authorization is live, no mode was recorded");
        return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE).body(body);
    }

    /** The one-line contract statement every console surface repeats. */
    private static String intentNote() {
        return "intent recorded only — self-hosted is the byte-identical default; the generator "
                + "(gate_backing_services at image time) and the ships-dark reconciler converge a "
                + "managed mode; tier-3 services are docs-only; managed creds route to "
                + "ESO/Vault, never this service";
    }
}
