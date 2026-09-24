package net.hugmesh.adminbff.matrixadmin;

import io.swagger.v3.oas.annotations.Operation;
import jakarta.validation.Valid;
import java.util.LinkedHashMap;
import java.util.Map;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;
import net.hugmesh.commons.web.ApiException;

/**
 * ADMIN-only, ONE-WAY Matrix account deactivate at {@code /bff/admin/matrix/deactivations}
 * (hugmesh-mod-bff-api#23; decision 83b = B puts it here, decision 83a = C gates it with two
 * calls). This is a different control from a moderator ban: a ban is a reversible
 * access_suspension; this posts tuwunel's {@code !admin users deactivate}, which has no undo.
 *
 * <ul>
 *   <li>{@code POST /propose} {@code {mxid}} -&gt; 201 with a single-use {@code token} bound to
 *       that account and to the calling admin, valid for {@code ttlSeconds}.</li>
 *   <li>{@code POST /confirm} {@code {mxid, token}} -&gt; 202 {@code posted:<event_id>} (the
 *       command is in the admin room; tuwunel applies it asynchronously), 502 when the post
 *       degraded (the token is spent either way), 403 {@code refused} with a {@code reason}
 *       for no token / unknown token (confirm without propose) / already used / expired /
 *       another account's token / another admin's token.</li>
 * </ul>
 * Both return 503 {@code dark:true} and write nothing while {@code matrix-admin.enabled=false}
 * (the default); 400 for a target that is not a plain MXID.
 *
 * <h3>Authorization</h3>
 * {@code SecurityConfig} gates {@code /bff/admin/**} to ADMIN|SUPERADMIN; each method adds
 * {@code @PreAuthorize("hasRole('ADMIN')")} per the decision. SUPERADMIN passes it through the
 * method-security role hierarchy ({@code ROLE_SUPERADMIN > ROLE_ADMIN}); MOD does not (ADMIN and
 * MOD are siblings). The target MXID lives on the ONE shared tuwunel, so an ADMIN of any brand
 * can name any account — there is no per-brand scoping of Matrix accounts to apply here.
 */
@RestController
@RequestMapping("/bff/admin/matrix/deactivations")
@Validated
public class MatrixAdminDeactivateController {

    private final MatrixDeactivateService service;

    public MatrixAdminDeactivateController(MatrixDeactivateService service) {
        this.service = service;
    }

    private static String subject(Authentication auth) {
        if (auth != null && auth.getPrincipal() instanceof Jwt jwt) {
            return jwt.getSubject();
        }
        return auth == null ? null : auth.getName();
    }

    @PreAuthorize("hasRole('ADMIN')")
    @Operation(summary = "Propose a one-way Matrix account deactivate (step 1 of 2)",
            operationId = "matrixDeactivatePropose")
    @PostMapping("/propose")
    public Mono<ResponseEntity<Map<String, Object>>> propose(
            @Valid @RequestBody MatrixDeactivateProposeRequest body, Authentication auth) {
        String actor = subject(auth);
        if (actor == null || actor.isBlank()) {
            return Mono.error(ApiException.unauthorized("no subject on token"));
        }
        return service.propose(actor, body.mxid())
                .map(MatrixAdminDeactivateController::proposed)
                .onErrorResume(e -> mapError(e));
    }

    @PreAuthorize("hasRole('ADMIN')")
    @Operation(summary = "Confirm a proposed Matrix account deactivate (step 2 of 2)",
            operationId = "matrixDeactivateConfirm")
    @PostMapping("/confirm")
    public Mono<ResponseEntity<Map<String, Object>>> confirm(
            @Valid @RequestBody MatrixDeactivateConfirmRequest body, Authentication auth) {
        String actor = subject(auth);
        if (actor == null || actor.isBlank()) {
            return Mono.error(ApiException.unauthorized("no subject on token"));
        }
        return service.confirm(actor, body.mxid(), body.token())
                .map(MatrixAdminDeactivateController::confirmed)
                .onErrorResume(e -> mapError(e));
    }

    private static ResponseEntity<Map<String, Object>> proposed(MatrixDeactivateService.Proposal p) {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("proposalId", p.proposalId());
        out.put("mxid", p.mxid());
        out.put("token", p.token());
        out.put("expiresAt", p.expiresAt().toString());
        out.put("ttlSeconds", p.ttlSeconds());
        out.put("oneWay", true);
        out.put("note", "Deactivating a Matrix account cannot be undone: tuwunel has no "
                + "re-activate. Confirm with this token before it expires.");
        return ResponseEntity.status(HttpStatus.CREATED).body(out);
    }

    /** 202 when the command reached the admin room; 502 when it did not (the token is spent). */
    private static ResponseEntity<Map<String, Object>> confirmed(MatrixDeactivateService.Confirmation c) {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("proposalId", c.proposalId());
        out.put("mxid", c.mxid());
        out.put("outcome", c.outcome().result());
        if (c.outcome().isPosted()) {
            out.put("note", "Command posted to the tuwunel admin room; tuwunel applies it "
                    + "asynchronously and its reply is not read back yet.");
            return ResponseEntity.status(HttpStatus.ACCEPTED).body(out);
        }
        out.put("note", "The deactivate was NOT posted. The token is spent; propose again "
                + "once the cause is fixed.");
        return ResponseEntity.status(HttpStatus.BAD_GATEWAY).body(out);
    }

    private static Mono<ResponseEntity<Map<String, Object>>> mapError(Throwable e) {
        Map<String, Object> out = new LinkedHashMap<>();
        if (e instanceof MatrixDeactivateService.RefusedException r) {
            out.put("refused", true);
            out.put("reason", r.refusal().code());
            return Mono.just(ResponseEntity.status(HttpStatus.FORBIDDEN).body(out));
        }
        if (e instanceof MatrixDeactivateService.DarkException) {
            out.put("dark", true);
            out.put("note", "the ADMIN Matrix deactivate ships dark (matrix-admin.enabled=false); "
                    + "nothing was recorded or sent");
            return Mono.just(ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE).body(out));
        }
        if (e instanceof MatrixDeactivateService.BadTargetException) {
            return Mono.error(ApiException.badRequest(e.getMessage()));
        }
        return Mono.error(e);
    }
}
