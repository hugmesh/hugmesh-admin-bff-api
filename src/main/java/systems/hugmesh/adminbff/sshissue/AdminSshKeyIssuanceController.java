package systems.hugmesh.adminbff.sshissue;

import io.swagger.v3.oas.annotations.Operation;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.core.io.buffer.DefaultDataBufferFactory;
import org.springframework.http.ContentDisposition;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
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
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import systems.hugmesh.authcore.casdoor.MfaStepUpService;
import systems.hugmesh.authcore.config.SessionCookieWebFilter;
import systems.hugmesh.commons.security.DomainRegistry;
import systems.hugmesh.commons.security.PrincipalDomain;
import systems.hugmesh.commons.web.ApiException;

import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Admin SSH key-ISSUANCE backend (SSH PR-4, Option B; ships dark) at
 * {@code /bff/admin/ssh-issue}. MINTS an Ed25519 credential for an operator to SSH into a
 * licensed device by registering its SHA256 fingerprint into the backing
 * {@code device_ssh_license} (the existing enforcement record the node pins), records a
 * NON-SECRET issuance audit row, and streams the one-time private key ONCE.
 *
 * <h3>Authorization (defence-in-depth)</h3>
 * The gateway + {@code SecurityConfig} gate {@code /bff/admin/**} to
 * {@code hasAnyRole('ADMIN','SUPERADMIN')}. ON TOP of that, every MUTATING verb and the
 * private-key download carry {@code @PreAuthorize("hasRole('SUPERADMIN')")} (v1 default —
 * SUPERADMIN-only avoids the step-up-mint ADMIN widening) AND require a valid
 * {@code X-SshKeyIssue-StepUp} token (validated by {@link SshKeyIssueStepUpGate}). The service
 * additionally enforces the fail-closed own-domain wall + superadmin-owned-node guard.
 *
 * <h3>SHIPS DARK</h3>
 * {@code app.ssh-issue.enabled=false} by default → mutating verbs return a 503 {@code dark:true}
 * descriptor and NEVER mint a key. The authorization (role + step-up + own-domain) is REAL and
 * runs BEFORE the dark check at the service boundary.
 *
 * <ul>
 *   <li>{@code POST   /bff/admin/ssh-issue/issue?deviceId=} — issue a credential.</li>
 *   <li>{@code GET    /bff/admin/ssh-issue/issued/{id}/private-key} — one-time private-key stream.</li>
 *   <li>{@code DELETE /bff/admin/ssh-issue/issued/{id}} — revoke a credential.</li>
 *   <li>{@code GET    /bff/admin/ssh-issue/devices/{deviceId}/issued-keys} — scoped list.</li>
 * </ul>
 */
@RestController
@RequestMapping("/bff/admin/ssh-issue")
@Validated
public class AdminSshKeyIssuanceController {

    private static final Logger log = LoggerFactory.getLogger(AdminSshKeyIssuanceController.class);
    private static final int MAX_ID = 36;

    private final AdminSshKeyIssuanceService service;
    private final SshKeyIssueStepUpGate stepUp;
    private final MfaStepUpService mfaStepUp;
    private final DomainRegistry domainRegistry;

    public AdminSshKeyIssuanceController(AdminSshKeyIssuanceService service,
                                         SshKeyIssueStepUpGate stepUp,
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

    private static String subject(Authentication auth) {
        if (auth != null && auth.getPrincipal() instanceof Jwt jwt) {
            return jwt.getSubject();
        }
        return auth == null ? null : auth.getName();
    }

    // ── issue ───────────────────────────────────────────────────────────────────────
    @PreAuthorize("hasRole('SUPERADMIN')")
    @Operation(summary = "Issue", operationId = "adminSshKeyIssuanceIssue")
    @PostMapping("/issue")
    public Mono<ResponseEntity<Map<String, Object>>> issue(
            @RequestParam @NotBlank @Size(max = MAX_ID) String deviceId,
            @RequestHeader(value = SshKeyIssueStepUpGate.STEP_UP_HEADER, required = false) String stepUpToken,
            @CookieValue(name = SessionCookieWebFilter.SESSION_COOKIE, required = false) String sessionCookie,
            @RequestHeader(name = HttpHeaders.AUTHORIZATION, required = false) String authHeader,
            Authentication auth) {
        String actor = subject(auth);
        if (actor == null || actor.isBlank()) {
            return Mono.error(ApiException.unauthorized("no subject on token"));
        }
        String sessionToken = SessionCookieWebFilter.bffTokenFrom(sessionCookie, authHeader);
        // A5 UNIFIED step-up: the workload step-up token OR a FRESH Casdoor-MFA stamp (co-equal,
        // license-INDEPENDENT). Issuance is a DEVICE op — the MFA leg satisfies ONLY the step-up
        // re-confirmation; the own-domain wall + device_ssh_license registration stay a SEPARATE
        // downstream check in service.issue(). Flag-gated + fail-closed via mfaStepUp.isFresh().
        // Check step-up, consume MFA single-use, then issue the SSH key.
        return mfaStepUp.isFresh(sessionToken)
                .flatMap(mfaFresh -> issueIfStepUpSatisfied(mfaFresh, actor, stepUpToken,
                        sessionToken, deviceId, auth));
    }

    // ── one-time private-key download ─────────────────────────────────────────────
    @PreAuthorize("hasRole('SUPERADMIN')")
    @Operation(summary = "Private key", operationId = "adminSshKeyIssuancePrivateKey")
    @GetMapping("/issued/{id}/private-key")
    public Mono<ResponseEntity<Flux<DataBuffer>>> privateKey(
            @PathVariable @NotBlank @Size(max = MAX_ID) String id,
            @RequestHeader(value = SshKeyIssueStepUpGate.STEP_UP_HEADER, required = false) String stepUpToken,
            @CookieValue(name = SessionCookieWebFilter.SESSION_COOKIE, required = false) String sessionCookie,
            @RequestHeader(name = HttpHeaders.AUTHORIZATION, required = false) String authHeader,
            Authentication auth) {
        String actor = subject(auth);
        if (actor == null || actor.isBlank()) {
            return Mono.error(ApiException.unauthorized("no subject on token"));
        }
        String sessionToken = SessionCookieWebFilter.bffTokenFrom(sessionCookie, authHeader);
        // Check step-up, consume MFA single-use, then stream the private key bytes.
        return mfaStepUp.isFresh(sessionToken)
                .flatMap(mfaFresh -> downloadKeyIfStepUpSatisfied(mfaFresh, actor, stepUpToken,
                        sessionToken, id));
    }

    // ── revoke ─────────────────────────────────────────────────────────────────────
    @PreAuthorize("hasRole('SUPERADMIN')")
    @Operation(summary = "Revoke", operationId = "adminSshKeyIssuanceRevoke")
    @DeleteMapping("/issued/{id}")
    public Mono<Map<String, Object>> revoke(
            @PathVariable @NotBlank @Size(max = MAX_ID) String id,
            @RequestHeader(value = SshKeyIssueStepUpGate.STEP_UP_HEADER, required = false) String stepUpToken,
            @CookieValue(name = SessionCookieWebFilter.SESSION_COOKIE, required = false) String sessionCookie,
            @RequestHeader(name = HttpHeaders.AUTHORIZATION, required = false) String authHeader,
            Authentication auth) {
        String actor = subject(auth);
        if (actor == null || actor.isBlank()) {
            return Mono.error(ApiException.unauthorized("no subject on token"));
        }
        String sessionToken = SessionCookieWebFilter.bffTokenFrom(sessionCookie, authHeader);
        // Check step-up, consume MFA single-use, then revoke the key record.
        return mfaStepUp.isFresh(sessionToken)
                .flatMap(mfaFresh -> revokeIfStepUpSatisfied(mfaFresh, actor, stepUpToken,
                        sessionToken, id, auth));
    }

    // ── list (read; allowed even while dark — authorization is real) ───────────────
    @PreAuthorize("hasAnyRole('ADMIN','SUPERADMIN')")
    @Operation(summary = "List for device", operationId = "adminSshKeyIssuanceListForDevice")
    @GetMapping("/devices/{deviceId}/issued-keys")
    public Mono<Map<String, Object>> listForDevice(
            @PathVariable @NotBlank @Size(max = MAX_ID) String deviceId,
            Authentication auth) {
        return service.listForDevice(deviceId, scope(auth)).collectList()
                .map(keys -> {
                    Map<String, Object> out = new LinkedHashMap<>();
                    out.put("deviceId", deviceId);
                    out.put("enabled", service.isEnabled());
                    out.put("issuedKeys", keys);
                    return out;
                });
    }

    /** Validate step-up then consume MFA single-use and revoke the issued key record. */
    private Mono<Map<String, Object>> revokeIfStepUpSatisfied(boolean mfaFresh, String actor,
                                                                String stepUpToken, String sessionToken,
                                                                String id, Authentication auth) {
        if (!stepUp.isSatisfied(actor, stepUpToken, mfaFresh)) {
            return Mono.error(ApiException.forbidden(
                    "revoke requires step-up re-authentication (present "
                    + SshKeyIssueStepUpGate.STEP_UP_HEADER + ")"));
        }
        Mono<Void> consume = mfaFresh ? mfaStepUp.consume(sessionToken) : Mono.empty();
        return consume.then(service.revoke(actor, id, scope(auth))
                .map(n -> Map.<String, Object>of("revoked", n == 1L, "id", id))
                .onErrorResume(AdminSshKeyIssuanceService.SshIssueDarkException.class,
                        e -> Mono.just(Map.of("dark", true, "revoked", false, "id", id))));
    }

    /** Validate step-up then consume MFA single-use and invoke the SSH key-issuance service. */
    private Mono<ResponseEntity<Map<String, Object>>> issueIfStepUpSatisfied(boolean mfaFresh,
                                                                               String actor,
                                                                               String stepUpToken,
                                                                               String sessionToken,
                                                                               String deviceId,
                                                                               Authentication auth) {
        if (!stepUp.isSatisfied(actor, stepUpToken, mfaFresh)) {
            return Mono.error(ApiException.forbidden(
                    "issue requires step-up re-authentication (present "
                    + SshKeyIssueStepUpGate.STEP_UP_HEADER + ")"));
        }
        Mono<Void> consume = mfaFresh ? mfaStepUp.consume(sessionToken) : Mono.empty();
        return consume.then(service.issue(actor, deviceId, scope(auth))
                .map(r -> ResponseEntity.ok(r.toMap()))
                .onErrorResume(AdminSshKeyIssuanceService.SshIssueDarkException.class,
                        e -> Mono.just(darkResponse()))
                .onErrorResume(AdminSshKeyIssuanceService.SshIssueDeniedException.class,
                        e -> Mono.error(ApiException.forbidden(e.getMessage()))));
    }

    /** Validate step-up then consume MFA single-use and stream the private key bytes. */
    private Mono<ResponseEntity<Flux<DataBuffer>>> downloadKeyIfStepUpSatisfied(boolean mfaFresh,
                                                                                  String actor,
                                                                                  String stepUpToken,
                                                                                  String sessionToken,
                                                                                  String id) {
        if (!stepUp.isSatisfied(actor, stepUpToken, mfaFresh)) {
            return Mono.error(ApiException.forbidden(
                    "private-key download requires step-up re-authentication (present "
                    + SshKeyIssueStepUpGate.STEP_UP_HEADER + ")"));
        }
        Mono<Void> consume = mfaFresh ? mfaStepUp.consume(sessionToken) : Mono.empty();
        return consume.then(service.downloadPrivateKey(actor, id)
                .map(bytes -> buildKeyDownloadResponse(bytes, id))
                .onErrorResume(AdminSshKeyIssuanceService.SshIssueDarkException.class,
                        e -> Mono.error(ApiException.serviceUnavailable(e.getMessage())))
                .onErrorResume(AdminSshKeyIssuanceService.SshIssueGoneException.class,
                        e -> Mono.error(ApiException.gone(e.getMessage()))));
    }

    /** Wrap the private key bytes in a one-shot streaming response with wipe-on-complete. */
    private static ResponseEntity<Flux<DataBuffer>> buildKeyDownloadResponse(byte[] bytes, String id) {
        // Stream the bytes, then WIPE the array in doFinally (never persisted/logged).
        DefaultDataBufferFactory factory = new DefaultDataBufferFactory();
        Flux<DataBuffer> body = Flux.<DataBuffer>just(factory.wrap(bytes))
                .doFinally(sig -> Arrays.fill(bytes, (byte) 0));
        HttpHeaders headers = new HttpHeaders();
        headers.setContentDisposition(ContentDisposition.attachment()
                .filename("hugmesh-ssh-" + safe(id)).build());
        return ResponseEntity.ok()
                .headers(headers)
                .contentType(MediaType.APPLICATION_OCTET_STREAM)
                .body(body);
    }

    private static ResponseEntity<Map<String, Object>> darkResponse() {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("dark", true);
        body.put("note", "admin SSH key-issuance ships dark (app.ssh-issue.enabled=false) — "
                + "authorization is live, no key was minted");
        return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE).body(body);
    }

    /** Keep the download filename free of path/CRLF surprises. */
    private static String safe(String id) {
        return id.replaceAll("[^A-Za-z0-9._-]", "_");
    }
}
