package systems.hugmesh.adminbff.appeal;

import io.swagger.v3.oas.annotations.Operation;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import systems.hugmesh.commons.security.DomainRegistry;
import systems.hugmesh.commons.security.PrincipalDomain;
import systems.hugmesh.commons.web.ApiException;

import java.util.Map;
import java.util.Set;

/**
 * The admin ACCOUNT-BAN appeal inbox at {@code /bff/admin/account-appeals} —
 * ADMIN/SUPERADMIN list the brand's appeals and decide them (approve / deny).
 *
 * <h3>Why ADMIN/SUPERADMIN only (not MOD)</h3>
 * The underlying mechanism a decide must reverse — {@code access_suspension} role
 * {@code PROFILE} — is written/cleared EXCLUSIVELY by {@code AdminController}'s
 * {@code /bff/admin/access-roles/**} endpoints, both {@code @PreAuthorize
 * ("hasRole('ADMIN')")}. MOD has no power to ban/unban an account in the first place
 * (that is the ACCOUNT-level domain this feature is about, as opposed to MOD's
 * CONTENT-moderation surface over federation-api {@code ModerationRequest} rows). Were
 * a MOD able to APPROVE an account appeal, they would gain indirect authority to
 * restore access they could never directly ban/lift — a privilege escalation the
 * existing {@code SuspensionService.clear} gate does not permit MOD to exercise
 * directly. So this decide surface deliberately matches the {@code hasRole('ADMIN')}
 * gate on the mechanism it drives, plus the SUPERADMIN cross-domain bypass every
 * sibling {@code /bff/admin/**} endpoint carries.
 *
 * <h3>Authorization</h3>
 * Mounted under {@code /bff/admin/**} (coarse gate {@code hasAnyRole('ADMIN',
 * 'SUPERADMIN')}); each method additionally carries its own
 * {@code @PreAuthorize("hasAnyRole('ADMIN','SUPERADMIN')")}. MOD/USER -&gt; 403. The
 * inbox + decide are brand-scoped via {@link PrincipalDomain} (validated issuer): a
 * scoped admin can only see/decide their own brand's appeals; SUPERADMIN unscoped.
 * Decide is a single-winner CAS {@code PENDING -> APPROVED/DENIED}; an APPROVE that
 * fails to restore the underlying suspension propagates as an error (never a
 * dishonest 200 with nothing actually restored — see {@link AccountAppealService#decide}).
 */
@RestController
@RequestMapping("/bff/admin/account-appeals")
@Validated
public class AccountAppealAdminController {

    private static final Logger log = LoggerFactory.getLogger(AccountAppealAdminController.class);

    /** The terminal statuses an admin may decide an appeal into. */
    private static final Set<String> DECIDABLE = Set.of(
            AccountAppeal.STATUS_APPROVED, AccountAppeal.STATUS_DENIED);

    private final AccountAppealService service;
    private final DomainRegistry domainRegistry;

    public AccountAppealAdminController(AccountAppealService service, DomainRegistry domainRegistry) {
        this.service = service;
        this.domainRegistry = domainRegistry;
    }

    private PrincipalDomain scope(Authentication auth) {
        return PrincipalDomain.of(auth, domainRegistry);
    }

    private static String actor(Authentication auth) {
        return auth == null ? "admin" : auth.getName();
    }

    /** The brand's appeal inbox (own brand; SUPERADMIN all). */
    @PreAuthorize("hasAnyRole('ADMIN','SUPERADMIN')")
    @Operation(summary = "List appeals", operationId = "accountAppealAdminList")
    @GetMapping("")
    public Flux<AccountAppeal> list(Authentication auth) {
        return service.listForAdmin(scope(auth));
    }

    /**
     * Decide an appeal: {@code POST /{id}/decide?status=APPROVED|DENIED}. CAS
     * {@code PENDING -> status}, brand-scoped, single-winner. APPROVE additionally
     * clears the appellant's {@code PROFILE} suspension BEFORE the appeal row flips —
     * a failure there is a 5xx (via the shared {@code ApiExceptionHandler}) and the
     * appeal stays {@code PENDING}, never a false "approved". An unknown status is a
     * 400; a no-op (already decided / absent / out of scope) returns
     * {@code decided:0}.
     */
    @PreAuthorize("hasAnyRole('ADMIN','SUPERADMIN')")
    @Operation(summary = "Decide appeal", operationId = "accountAppealAdminDecide")
    @PostMapping("/{id}/decide")
    public Mono<ResponseEntity<Map<String, Object>>> decide(
            @PathVariable @NotBlank @Size(max = 36) String id,
            @RequestParam @NotBlank @Size(max = 16) String status,
            Authentication auth) {
        String s = status.trim().toUpperCase();
        if (!DECIDABLE.contains(s)) {
            return Mono.error(ApiException.badRequest("status must be one of APPROVED|DENIED"));
        }
        return service.decide(id, s, actor(auth), scope(auth))
                .doOnNext(n -> log.info("[account-appeal] admin decide id={} -> {} by={} rows={}",
                        id, s, actor(auth), n))
                .map(n -> ResponseEntity.ok(Map.of("decided", n, "status", s)));
    }
}
