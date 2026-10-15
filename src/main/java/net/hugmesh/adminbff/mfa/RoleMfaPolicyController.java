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
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;

import java.util.List;

/**
 * Admin surface for the per-(domain, role) MFA requirement policy ({@code role_mfa_policy},
 * changeSet 150) — the first slice of the "per-role MFA defaults" leg of
 * hugmesh-admin-bff-api#3.
 *
 * <p>Read/write only: nothing in this controller enforces the policy. An admin can see the
 * effective posture for their brand and set the relaxable rows; the consumer is
 * {@link RoleMfaPolicyEnforcementFilter}, which is absent unless
 * {@value RoleMfaPolicyEnforcementFilter#FLAG} is {@code true}.
 *
 * <p>Security, in layers exactly as {@code /bff/admin/oidc-providers}: the gateway
 * {@code /bff/admin/**} route-access row, the {@code SecurityConfig} path gate
 * ({@code hasAnyRole('ADMIN','SUPERADMIN')}), and the per-method
 * {@code @PreAuthorize("hasRole('ADMIN')")}. The {@code domain} every read and write is
 * keyed on comes from the token's VALIDATED issuer via {@link PrincipalDomain}, never from
 * the request, with ONE exception: a SUPERADMIN may name another known domain in the optional
 * {@code domain} query parameter (operator decision 46, hugmesh-generator#347), matching
 * {@code DomainCapabilityAdminController}. Unlike the OIDC-provider controller this one refuses (403) a principal whose
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

    /**
     * The effective policy for every canonical role (plus any extra role with a row). An ADMIN
     * always gets their own domain; a SUPERADMIN gets their home domain, or any known domain
     * named by the optional {@code domain} query parameter.
     */
    @PreAuthorize("hasRole('ADMIN')")
    @Operation(summary = "List role MFA policies", operationId = "roleMfaPolicyList")
    @GetMapping
    public Mono<RoleMfaPolicyList> list(
            @RequestParam(name = "domain", required = false) @Size(max = 255) String domain,
            Authentication auth) {
        PrincipalDomain scope = scopeOf(auth, domain);
        return policies.listEffective(scope.domain())
                .collectList()
                .map(list -> new RoleMfaPolicyList(scope.domain(), list));
    }

    /**
     * Upsert one role's policy. An ADMIN writes their own domain only; a SUPERADMIN writes their
     * home domain, or any known domain named by the optional {@code domain} query parameter.
     * Relaxing a floor role ({@code superadmin} / {@code admin}) is refused with 400 before any
     * write.
     */
    @PreAuthorize("hasRole('ADMIN')")
    @Operation(summary = "Set a role MFA policy", operationId = "roleMfaPolicySet")
    @PutMapping("/{role}")
    public Mono<RoleMfaPolicy> set(
            @PathVariable @Size(max = 64) @Pattern(regexp = "[A-Za-z0-9_-]+") String role,
            @Valid @RequestBody SetRoleMfaPolicyRequest body,
            @RequestParam(name = "domain", required = false) @Size(max = 255) String domain,
            Authentication auth) {
        PrincipalDomain scope = scopeOf(auth, domain);
        List<String> methods = body.methods() == null ? List.of() : body.methods();
        return policies.upsert(scope.domain(), role, body.required(), methods,
                body.graceSeconds(), auth.getName());
    }

    /**
     * The domain a request acts on. The caller's own domain always comes from the validated
     * issuer. {@code requested} (the {@code domain} query parameter) can only redirect a
     * SUPERADMIN, and only to a domain the registry knows: for anyone else a value other than
     * their own domain is a 403, so a request parameter can never move an ADMIN across brands.
     */
    private PrincipalDomain scopeOf(Authentication auth, String requested) {
        PrincipalDomain scope = PrincipalDomain.of(auth, domainRegistry);
        boolean named = requested != null && !requested.isBlank();
        if (named && scope.superadmin() && !requested.equals(scope.domain())) {
            if (!domainRegistry.isKnownDomain(requested)) {
                throw ApiException.badRequest("unknown domain '" + requested + "'");
            }
            return PrincipalDomain.superadminFor(requested);
        }
        if (PrincipalDomain.NO_DOMAIN.equals(scope.domain())) {
            throw ApiException.forbidden("cannot resolve the caller's domain from the validated issuer");
        }
        if (named && !requested.equals(scope.domain())) {
            throw ApiException.forbidden("an admin may only act on their own domain");
        }
        return scope;
    }
}
