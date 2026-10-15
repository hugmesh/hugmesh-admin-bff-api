package net.hugmesh.adminbff.mfa;

import io.swagger.v3.oas.annotations.Operation;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import java.util.ArrayList;
import java.util.Collections;
import net.hugmesh.commons.security.DomainRegistry;
import net.hugmesh.commons.security.PrincipalDomain;
import net.hugmesh.commons.web.ApiException;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;

import java.util.List;

/**
 * Admin surface for the per-(domain, role) MFA requirement policy ({@code role_mfa_policy},
 * changeSet 150) — the first slice of the "per-role MFA defaults" leg of
 * hugmesh-admin-bff-api#3.
 *
 * <p>Read/write only: nothing here (or anywhere yet) enforces the policy on a request. An
 * admin can see the effective posture for their brand and set the relaxable rows before the
 * consumer wave wires {@link RoleMfaPolicyService#requiredForAny} into the session seams.
 *
 * <p>Security, in layers exactly as {@code /bff/admin/oidc-providers}: the gateway
 * {@code /bff/admin/**} route-access row, the {@code SecurityConfig} path gate
 * ({@code hasAnyRole('ADMIN','SUPERADMIN')}), and the per-method
 * {@code @PreAuthorize("hasRole('ADMIN')")}. The {@code domain} every read and write is
 * keyed on comes from the token's VALIDATED issuer via {@link PrincipalDomain}, never from
 * the request. Unlike the OIDC-provider controller this one refuses (403) a principal whose
 * domain cannot be resolved — an MFA policy written under the {@code NO_DOMAIN} sentinel
 * would be a row no real brand ever reads, and the safer failure is to write nothing.
 */
@RestController
@RequestMapping("/bff/admin/mfa/role-policy")
@Validated
public class RoleMfaPolicyController {

    private final RoleMfaPolicyService policies;
    private final DomainRegistry domainRegistry;

    public RoleMfaPolicyController(RoleMfaPolicyService policies, DomainRegistry domainRegistry) {
        this.policies = policies;
        this.domainRegistry = domainRegistry;
    }

    /** Response envelope for the listing. */
    public record RoleMfaPolicyList(String domain, List<RoleMfaPolicy> policies) {

        public RoleMfaPolicyList {
            policies = policies == null ? null : Collections.unmodifiableList(new ArrayList<>(policies));
        }}

    /**
     * Request body for setting one role's policy.
     *
     * @param required     whether MFA is required for the role (a floor role only accepts {@code true})
     * @param methods      allowed methods ({@code webauthn} / {@code otp} / {@code recovery}); empty = any
     * @param graceSeconds re-prompt grace window; {@code 0} = always re-prompt
     */
    public record SetRoleMfaPolicyRequest(
            boolean required,
            @Size(max = 3, message = "at most 3 methods")
            List<@NotBlank @Size(max = 16) String> methods,
            @Min(0) @Max(RoleMfaPolicyService.MAX_GRACE_SECONDS) long graceSeconds) {

        public SetRoleMfaPolicyRequest {
            methods = methods == null ? null : Collections.unmodifiableList(new ArrayList<>(methods));
        }}

    /** The effective policy for every canonical role (plus any extra role with a row) in the acting admin's domain. */
    @PreAuthorize("hasRole('ADMIN')")
    @Operation(summary = "List role MFA policies", operationId = "roleMfaPolicyList")
    @GetMapping
    public Mono<RoleMfaPolicyList> list(Authentication auth) {
        PrincipalDomain scope = scopeOf(auth);
        return policies.listEffective(scope.domain())
                .collectList()
                .map(list -> new RoleMfaPolicyList(scope.domain(), list));
    }

    /**
     * Upsert one role's policy in the acting admin's domain. Relaxing a floor role
     * ({@code superadmin} / {@code admin}) is refused with 400 before any write.
     */
    @PreAuthorize("hasRole('ADMIN')")
    @Operation(summary = "Set a role MFA policy", operationId = "roleMfaPolicySet")
    @PutMapping("/{role}")
    public Mono<RoleMfaPolicy> set(
            @PathVariable @Size(max = 64) @Pattern(regexp = "[A-Za-z0-9_-]+") String role,
            @Valid @RequestBody SetRoleMfaPolicyRequest body,
            Authentication auth) {
        PrincipalDomain scope = scopeOf(auth);
        List<String> methods = body.methods() == null ? List.of() : body.methods();
        return policies.upsert(scope.domain(), role, body.required(), methods,
                body.graceSeconds(), auth.getName());
    }

    private PrincipalDomain scopeOf(Authentication auth) {
        PrincipalDomain scope = PrincipalDomain.of(auth, domainRegistry);
        if (PrincipalDomain.NO_DOMAIN.equals(scope.domain())) {
            throw ApiException.forbidden("cannot resolve the caller's domain from the validated issuer");
        }
        return scope;
    }
}
