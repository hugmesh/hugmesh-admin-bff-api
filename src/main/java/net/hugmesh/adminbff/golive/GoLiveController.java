package net.hugmesh.adminbff.golive;

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
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;
import net.hugmesh.authcore.casdoor.MfaStepUpService;
import net.hugmesh.authcore.config.SessionCookieWebFilter;
import net.hugmesh.commons.web.ApiException;
import net.hugmesh.adminbff.web.StepUpRequiredException;
import net.hugmesh.adminbff.web.dto.RecordGoLiveIntentRequest;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * SUPERADMIN GO-LIVE WIZARD backend (reactive WebFlux; ships dark) at
 * {@code /bff/admin/go-live} — the admin web-UI half of go-live wizard v1, MIRRORING the
 * {@link net.hugmesh.adminbff.imagegen.ImageBuildController} controller/service/
 * step-up shape and the {@link
 * net.hugmesh.adminbff.domainregistry.DomainRegistryController} signed-export shape.
 *
 * <h3>INTENT ONLY — the pinned contract</h3>
 * {@code /etc/hugmesh/go-live} is a HOST file an in-cluster pod can never write. This
 * controller therefore RECORDS SIGNED INTENT ONLY: {@code POST /intents} persists a
 * {@code recorded} row; the host-side go-live agent pulls {@code GET /export} (detached
 * Ed25519 over canonical bytes, strict-monotonic generation), verifies against the
 * key-USB-baked public half, writes the marker itself, and acks {@code applied}. Every
 * response from the record path says so explicitly ({@code applied:false} + a hostAgent
 * note) — this service NEVER pretends it flipped the marker.
 *
 * <h3>Authorization (defence-in-depth)</h3>
 * The gateway + {@code SecurityConfig} gate {@code /bff/admin/**} to
 * {@code hasAnyRole('ADMIN','SUPERADMIN')}. ON TOP of that, EVERY endpoint here adds
 * {@code @PreAuthorize("hasRole('SUPERADMIN')")} (taking a brand public is cross-domain
 * infra, above a brand admin — same wall as the domain registry), and the MUTATING verbs
 * additionally require a valid {@code X-GoLive-StepUp} token ({@link GoLiveStepUpGate},
 * A5-unified with a fresh Casdoor-MFA stamp) — the design's "human confirm step".
 *
 * <h3>SHIPS DARK</h3>
 * {@code app.go-live.enabled=false} by default → mutating verbs return a 503
 * {@code dark:true} descriptor and write NOTHING; reads (status/providers/export) stay live
 * so the wizard renders honestly and the host agent's export channel is testable.
 *
 * <ul>
 *   <li>{@code GET    /bff/admin/go-live} — wizard status: enabled flag + intent history.</li>
 *   <li>{@code GET    /bff/admin/go-live/providers} — the declarative v1 provider catalog.</li>
 *   <li>{@code POST   /bff/admin/go-live/intents} — record an intent (step-up).</li>
 *   <li>{@code DELETE /bff/admin/go-live/intents/{id}} — withdraw an intent (step-up).</li>
 *   <li>{@code GET    /bff/admin/go-live/export} — the SIGNED intent export the host
 *       go-live agent consumes (SUPERADMIN | internal mTLS, like the domain export).</li>
 * </ul>
 */
@RestController
@RequestMapping("/bff/admin/go-live")
@Validated
public class GoLiveController {

    private static final int MAX_ID = 36;

    private final GoLiveService service;
    private final GoLiveExportService export;
    private final GoLiveStepUpGate stepUp;
    private final MfaStepUpService mfaStepUp;

    public GoLiveController(GoLiveService service,
                            GoLiveExportService export,
                            GoLiveStepUpGate stepUp,
                            MfaStepUpService mfaStepUp) {
        this.service = service;
        this.export = export;
        this.stepUp = stepUp;
        this.mfaStepUp = mfaStepUp;
    }

    private static String subject(Authentication auth) {
        if (auth != null && auth.getPrincipal() instanceof Jwt jwt) {
            return jwt.getSubject();
        }
        return auth == null ? null : auth.getName();
    }

    // ── status + history (read; live even while dark) ───────────────────────────────
    @PreAuthorize("hasRole('SUPERADMIN')")
    @Operation(summary = "Status", operationId = "goLiveStatus")
    @GetMapping
    public Mono<Map<String, Object>> status() {
        return service.history().map(GoLiveIntent::toMap).collectList()
                .map(intents -> {
                    Map<String, Object> out = new LinkedHashMap<>();
                    out.put("enabled", service.isEnabled());
                    out.put("intents", intents);
                    // The honesty banner the wizard renders: recording here NEVER flips the
                    // host marker — the host agent does, off the signed export.
                    out.put("hostAgent", hostAgentNote());
                    return out;
                });
    }

    // ── provider catalog (read; static, non-secret) ────────────────────────────────
    @PreAuthorize("hasRole('SUPERADMIN')")
    @Operation(summary = "Providers", operationId = "goLiveProviders")
    @GetMapping("/providers")
    public Mono<Map<String, Object>> providers() {
        List<GoLiveProviderCatalog.GoLiveProvider> providers = service.providers();
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("providers", providers);
        out.put("exposureModels", List.of(GoLiveProviderCatalog.MODEL_TUNNEL,
                GoLiveProviderCatalog.MODEL_PUBLIC_DNS, GoLiveProviderCatalog.MODEL_FUNNEL));
        return Mono.just(out);
    }

    // ── record an intent (mutating; step-up; dark -> 503) ──────────────────────────
    @PreAuthorize("hasRole('SUPERADMIN')")
    @Operation(summary = "Record intent", operationId = "goLiveRecordIntent")
    @PostMapping("/intents")
    public Mono<ResponseEntity<Map<String, Object>>> recordIntent(
            @Valid @RequestBody RecordGoLiveIntentRequest body,
            @RequestHeader(value = GoLiveStepUpGate.STEP_UP_HEADER, required = false) String stepUpToken,
            @CookieValue(name = SessionCookieWebFilter.SESSION_COOKIE, required = false) String sessionCookie,
            @RequestHeader(name = HttpHeaders.AUTHORIZATION, required = false) String authHeader,
            Authentication auth) {
        String actor = subject(auth);
        if (actor == null || actor.isBlank()) {
            return Mono.error(ApiException.unauthorized("no subject on token"));
        }
        // The caller's opaque bff_ session (cookie OR synthesised-from-bearer), derived exactly
        // as ImageBuildController / AdminSshKeyIssuanceController do — NEVER a body field.
        String sessionToken = SessionCookieWebFilter.bffTokenFrom(sessionCookie, authHeader);
        // Check step-up, consume the MFA single-use, then record the intent.
        return mfaStepUp.isFresh(sessionToken)
                .flatMap(mfaFresh -> recordIfStepUpSatisfied(mfaFresh, actor, stepUpToken,
                        sessionToken, body));
    }

    // ── withdraw an intent (mutating; step-up; dark -> 503) ────────────────────────
    @PreAuthorize("hasRole('SUPERADMIN')")
    @Operation(summary = "Withdraw intent", operationId = "goLiveWithdrawIntent")
    @DeleteMapping("/intents/{id}")
    public Mono<ResponseEntity<Map<String, Object>>> withdrawIntent(
            @PathVariable @NotBlank @Size(max = MAX_ID) String id,
            @RequestHeader(value = GoLiveStepUpGate.STEP_UP_HEADER, required = false) String stepUpToken,
            @CookieValue(name = SessionCookieWebFilter.SESSION_COOKIE, required = false) String sessionCookie,
            @RequestHeader(name = HttpHeaders.AUTHORIZATION, required = false) String authHeader,
            Authentication auth) {
        String actor = subject(auth);
        if (actor == null || actor.isBlank()) {
            return Mono.error(ApiException.unauthorized("no subject on token"));
        }
        String sessionToken = SessionCookieWebFilter.bffTokenFrom(sessionCookie, authHeader);
        // Check step-up, consume the MFA single-use, then CAS-withdraw the intent row.
        return mfaStepUp.isFresh(sessionToken)
                .flatMap(mfaFresh -> withdrawIfStepUpSatisfied(mfaFresh, actor, stepUpToken,
                        sessionToken, id));
    }

    // ── signed intent export (SUPERADMIN | internal mTLS) ──────────────────────────
    /**
     * The signed {@code go_live_intent} export the HOST-SIDE go-live agent consumes — the one
     * channel the wizard effects go-live through (contract: intent only). Canonical
     * line-oriented bytes + detached Ed25519 + monotonic generation; the agent verifies
     * against the key-USB-baked public half and FAIL-CLOSES (keeps last-good, applies
     * nothing) on an unsigned / tampered / rolled-back payload. Same {@code SUPERADMIN |
     * internal-mTLS} gate as the domain-registry export; the optional {@code node}
     * fingerprint is pinned into the header as PROVENANCE only. Live even while dark so the
     * channel is testable end-to-end before enablement (an empty/dark ledger is an empty
     * signed body — nothing to apply).
     */
    @PreAuthorize("hasRole('SUPERADMIN')")
    @Operation(summary = "Export", operationId = "goLiveExport")
    @GetMapping("/export")
    public Mono<GoLiveExportModels.SignedGoLiveExport> export(
            @RequestParam(value = "node", required = false) @Size(max = 128) String node) {
        return export.exportIntents(node);
    }

    // ── step-up-gated bodies (clone of the ssh-issue controller helpers) ────────────

    /** Validate step-up, consume the MFA single-use, then record — mapping dark -> 503 and
     *  vocabulary refusals -> 400. The success body is EXPLICIT about the contract:
     *  {@code applied:false} + the hostAgent note (recording never flips the marker). */
    private Mono<ResponseEntity<Map<String, Object>>> recordIfStepUpSatisfied(
            boolean mfaFresh, String actor, String stepUpToken, String sessionToken,
            RecordGoLiveIntentRequest body) {
        if (!stepUp.isSatisfied(actor, stepUpToken, mfaFresh)) {
            return Mono.error(StepUpRequiredException.forRetryHeader(
                    GoLiveStepUpGate.STEP_UP_HEADER, "recording a go-live intent"));
        }
        Mono<Void> consume = mfaFresh ? mfaStepUp.consume(sessionToken) : Mono.empty();
        return consume.then(service.record(actor, body)
                .map(intent -> {
                    Map<String, Object> out = new LinkedHashMap<>(intent.toMap());
                    out.put("hostAgent", hostAgentNote());
                    return ResponseEntity.ok(out);
                })
                .onErrorResume(GoLiveService.GoLiveDarkException.class,
                        e -> Mono.just(darkResponse()))
                .onErrorResume(GoLiveService.GoLiveValidationException.class,
                        e -> Mono.error(ApiException.badRequest(e.getMessage()))));
    }

    /** Validate step-up, consume the MFA single-use, then CAS-withdraw. */
    private Mono<ResponseEntity<Map<String, Object>>> withdrawIfStepUpSatisfied(
            boolean mfaFresh, String actor, String stepUpToken, String sessionToken, String id) {
        if (!stepUp.isSatisfied(actor, stepUpToken, mfaFresh)) {
            return Mono.error(StepUpRequiredException.forRetryHeader(
                    GoLiveStepUpGate.STEP_UP_HEADER, "withdrawing a go-live intent"));
        }
        Mono<Void> consume = mfaFresh ? mfaStepUp.consume(sessionToken) : Mono.empty();
        return consume.then(service.withdraw(actor, id)
                .map(n -> ResponseEntity.ok(
                        Map.<String, Object>of("withdrawn", n == 1L, "id", id)))
                .onErrorResume(GoLiveService.GoLiveDarkException.class,
                        e -> Mono.just(darkResponse())));
    }

    /** The 503 descriptor the mutating verbs return while dark — nothing was written. */
    private static ResponseEntity<Map<String, Object>> darkResponse() {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("dark", true);
        body.put("note", "go-live wizard ships dark (app.go-live.enabled=false) — "
                + "authorization is live, no intent was written");
        return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE).body(body);
    }

    /** The one-line contract statement every wizard surface repeats. */
    private static String hostAgentNote() {
        return "intent recorded only — the host-side go-live agent verifies the signed export "
                + "and writes /etc/hugmesh/go-live itself (reconcile converges <=60s); "
                + "this service never flips the marker";
    }
}
