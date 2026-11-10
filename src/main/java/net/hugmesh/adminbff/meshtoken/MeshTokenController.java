package net.hugmesh.adminbff.meshtoken;

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
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;
import net.hugmesh.adminbff.mfa.PrincipalSessionToken;
import net.hugmesh.adminbff.web.StepUpRequiredException;
import net.hugmesh.authcore.casdoor.MfaStepUpService;
import net.hugmesh.authcore.config.SessionCookieWebFilter;
import net.hugmesh.commons.security.DomainRegistry;
import net.hugmesh.commons.security.PrincipalDomain;
import net.hugmesh.commons.web.ApiException;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * HugMesh-token issuing for the web admin UI, at {@code /bff/admin/mesh-tokens}. SHIPS DARK
 * ({@code app.mesh-token.enabled=false}).
 *
 * <ul>
 *   <li>{@code GET  /bff/admin/mesh-tokens/issuer} — the issuer's public key, its {@code SHA256:}
 *       fingerprint (shown wherever tokens are handed out, so recipients can compare it), the
 *       mesh, and the domains and roles THIS caller may issue for.</li>
 *   <li>{@code POST /bff/admin/mesh-tokens} — issue one token. The token is in this response
 *       and nowhere else: it is not stored and cannot be fetched again.</li>
 *   <li>{@code GET  /bff/admin/mesh-tokens} — the audit trail (never a token or key).</li>
 * </ul>
 *
 * <h2>Authorization</h2>
 * The gateway and {@code SecurityConfig} admit only ADMIN/SUPERADMIN to {@code /bff/admin/**}
 * (and the front-end route row is {@code mfa_required}); each method repeats
 * {@code hasAnyRole('ADMIN','SUPERADMIN')}. POST also needs a step-up ({@code X-MeshToken-StepUp}
 * or a fresh MFA stamp, consumed single-use), and the service enforces the own-domain wall and
 * the role/shell rules ({@link MeshTokenService}).
 */
@RestController
@RequestMapping("/bff/admin/mesh-tokens")
@Validated
public class MeshTokenController {

    private final MeshTokenService service;
    private final MeshTokenStepUpGate stepUp;
    private final MfaStepUpService mfaStepUp;
    private final DomainRegistry domainRegistry;

    public MeshTokenController(MeshTokenService service, MeshTokenStepUpGate stepUp,
                               MfaStepUpService mfaStepUp, DomainRegistry domainRegistry) {
        this.service = service;
        this.stepUp = stepUp;
        this.mfaStepUp = mfaStepUp;
        this.domainRegistry = domainRegistry;
    }

    /** The grant an admin asks for. Shapes only here; the rules live in the service. */
    public record MeshTokenIssueRequest(
            @NotBlank @Size(max = 253) String domain,
            @NotBlank @Size(max = 16) String role,
            boolean shell,
            Long lifetimeSeconds,
            @Size(max = 63) String nodeName) {
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

    @PreAuthorize("hasAnyRole('ADMIN','SUPERADMIN')")
    @Operation(summary = "The mesh-token issuer: public key, fingerprint, domains and roles this caller may issue",
            operationId = "meshTokenIssuer")
    @GetMapping("/issuer")
    public Mono<Map<String, Object>> issuer(Authentication auth) {
        return Mono.fromSupplier(() -> service.issuer(scope(auth)));
    }

    @PreAuthorize("hasAnyRole('ADMIN','SUPERADMIN')")
    @Operation(summary = "The mesh-token audit trail (never a token or key)", operationId = "meshTokenList")
    @GetMapping
    public Mono<Map<String, Object>> list(Authentication auth) {
        return service.list(scope(auth)).collectList().map(rows -> {
            Map<String, Object> out = new LinkedHashMap<>();
            out.put("enabled", service.isEnabled());
            out.put("issued", rows);
            return out;
        });
    }

    @PreAuthorize("hasAnyRole('ADMIN','SUPERADMIN')")
    @Operation(summary = "Issue one HugMesh token (returned once, never stored)", operationId = "meshTokenIssue")
    @PostMapping
    public Mono<ResponseEntity<Map<String, Object>>> issue(
            @Valid @RequestBody MeshTokenIssueRequest body,
            @RequestHeader(value = MeshTokenStepUpGate.STEP_UP_HEADER, required = false) String stepUpToken,
            @CookieValue(name = SessionCookieWebFilter.SESSION_COOKIE, required = false) String sessionCookie,
            @RequestHeader(name = HttpHeaders.AUTHORIZATION, required = false) String authHeader,
            Authentication auth) {
        String actor = subject(auth);
        if (actor == null || actor.isBlank()) {
            return Mono.error(ApiException.unauthorized("no subject on token"));
        }
        String sessionToken = PrincipalSessionToken.of(sessionCookie, authHeader);
        // Check step-up, consume MFA single-use, then issue.
        return mfaStepUp.isFresh(sessionToken)
                .flatMap(mfaFresh -> issueIfStepUpSatisfied(mfaFresh, actor, stepUpToken, sessionToken, body, auth));
    }

    /** Validate step-up, consume the MFA stamp single-use, then issue. */
    private Mono<ResponseEntity<Map<String, Object>>> issueIfStepUpSatisfied(boolean mfaFresh, String actor,
                                                                              String stepUpToken, String sessionToken,
                                                                              MeshTokenIssueRequest body, Authentication auth) {
        if (!stepUp.isSatisfied(actor, stepUpToken, mfaFresh)) {
            return Mono.error(StepUpRequiredException.forRetryHeader(
                    MeshTokenStepUpGate.STEP_UP_HEADER, "mesh-token issue"));
        }
        Mono<Void> consume = mfaFresh ? mfaStepUp.consume(sessionToken) : Mono.empty();
        MeshTokenService.IssueRequest req = new MeshTokenService.IssueRequest(
                body.domain(), body.role(), body.shell(), body.lifetimeSeconds(), body.nodeName());
        return consume.then(service.issue(actor, scope(auth), req)
                .map(r -> ResponseEntity.ok(r.toMap()))
                .onErrorResume(MeshTokenService.MeshTokenDarkException.class, e -> Mono.just(darkResponse()))
                .onErrorResume(MeshTokenService.MeshTokenDeniedException.class,
                        e -> Mono.error(ApiException.forbidden(e.getMessage())))
                .onErrorResume(MeshTokenService.MeshTokenInvalidException.class,
                        e -> Mono.error(ApiException.badRequest(e.getMessage())))
                .onErrorResume(HeadscalePreAuthKeyClient.HeadscaleUnavailableException.class,
                        e -> Mono.error(ApiException.serviceUnavailable(e.getMessage()))));
    }

    private static ResponseEntity<Map<String, Object>> darkResponse() {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("dark", true);
        body.put("note", MeshTokenService.DARK_NOTE);
        return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE).body(body);
    }
}
