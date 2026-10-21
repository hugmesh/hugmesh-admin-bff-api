package net.hugmesh.adminbff.oidcprovider;

import io.swagger.v3.oas.annotations.Operation;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import java.util.ArrayList;
import java.util.Collections;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Mono;
import net.hugmesh.commons.security.DomainRegistry;
import net.hugmesh.commons.security.PrincipalDomain;

import net.hugmesh.commons.web.ApiException;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * Admin/superadmin endpoint for configuring which Casdoor roles new users
 * automatically receive when registering via a given OIDC identity provider.
 *
 * <p>When an admin configures an OIDC provider (Google, GitHub, or a custom OIDC)
 * in Casdoor, they can also declare which roles should be assigned to every new
 * account that comes through that provider. Roles are stored per-domain so each
 * brand's admin only controls their own provider-role mappings.
 *
 * <p><b>Registration-flow integration</b>: the mappings configured here ARE applied
 * automatically on new-user registration via {@link OidcFirstLoginController} (the
 * {@code POST /bff/internal/oidc/first-login} apply endpoint, which reads
 * {@link OidcProviderRoleRepository#rolesFor}) plus a scheduled first-login probe in
 * {@code hugmesh-actions} ({@code OidcDefaultRoleProbeAction}) that detects newly-created
 * Casdoor users and invokes it. The probe is DARK BY DEFAULT
 * ({@code app.actions.oidc-default-roles.enabled=false} in hugmesh-actions) pending an
 * operator opting in per-environment (it also requires a real
 * {@code APP_OIDC_DEFAULT_ROLES_INTERNAL_TOKEN} and a non-empty provider-map to do anything);
 * the full probe-to-apply chain is covered by unit/slice tests in both repos
 * ({@code OidcDefaultRoleProbeActionTest}, {@code OidcRoleHookClientTest},
 * {@code OidcFirstLoginControllerTest}) but has not been exercised against a live Casdoor.
 * Until an operator flips the probe on for an environment, admins can still see and edit
 * the mappings here; they are simply not yet being applied automatically there.
 *
 * <p>Security: {@code /bff/admin/**} is gated at the fe-gateway + the resource-server
 * filter chain; these methods additionally require {@code ROLE_ADMIN}.
 */
@RestController
@RequestMapping("/bff/admin/oidc-providers")
@Validated
public class OidcProviderRolesController {

    private final OidcProviderRoleRepository repo;
    private final DomainRegistry domainRegistry;

    public OidcProviderRolesController(OidcProviderRoleRepository repo, DomainRegistry domainRegistry) {
        this.repo = repo;
        this.domainRegistry = domainRegistry;
    }

    /**
     * List all OIDC providers that have configured default roles, grouped by
     * provider name.
     *
     * <p>Response shape (scoped to the acting admin's domain):
     * <pre>
     * {
     *   "providers": [
     *     { "provider": "google", "roles": ["user", "mod"] },
     *     { "provider": "github", "roles": ["user"] }
     *   ]
     * }
     * </pre>
     */
    @PreAuthorize("hasRole('ADMIN')")
    @Operation(summary = "List provider roles", operationId = "oidcProviderRolesListProviderRoles")
    @GetMapping("/roles")
    public Mono<Map<String, Object>> listProviderRoles(Authentication auth) {
        PrincipalDomain scope = PrincipalDomain.of(auth, domainRegistry);
        return repo.listByDomain(scope.domain())
                .collect(Collectors.groupingBy(
                        OidcProviderRole::provider,
                        LinkedHashMap::new,
                        Collectors.mapping(OidcProviderRole::roleName, Collectors.toList())))
                .map(grouped -> {
                    List<Map<String, Object>> providers = grouped.entrySet().stream()
                            .map(e -> Map.of("provider", (Object) e.getKey(), "roles", e.getValue()))
                            .toList();
                    return Map.of("providers", (Object) providers);
                });
    }

    /**
     * Request body for setting default roles for a provider.
     *
     * @param roles lowercase Casdoor role names (e.g. "user", "mod"); empty list
     *              clears all roles for the provider.
     */
    public record SetRolesRequest(
            @Size(max = 20, message = "at most 20 roles per provider")
            List<@NotBlank @Size(max = 64) @Pattern(regexp = "[a-z0-9_-]+",
                    message = "role names must be lowercase alphanumeric") String> roles) {

        public SetRolesRequest {
            roles = roles == null ? null : Collections.unmodifiableList(new ArrayList<>(roles));
        }}

    /**
     * Replace the default role set for a specific OIDC provider.
     * An empty {@code roles} list clears the mapping (new users from this provider
     * get no auto-assigned roles other than the Casdoor default).
     *
     * @param provider Casdoor identity-provider name (e.g. "google", "github",
     *                 "custom-oidc-company"). Case-insensitive (folded to lower).
     */
    @PreAuthorize("hasRole('ADMIN')")
    @Operation(summary = "Set provider roles", operationId = "oidcProviderRolesSetProviderRoles")
    @PutMapping("/{provider}/roles")
    public Mono<Map<String, Object>> setProviderRoles(
            @PathVariable @Size(max = 64) @Pattern(regexp = "[A-Za-z0-9_-]+") String provider,
            @Valid @RequestBody SetRolesRequest body,
            Authentication auth) {
        PrincipalDomain scope = PrincipalDomain.of(auth, domainRegistry);
        String providerKey = provider.toLowerCase();
        List<String> requested = body.roles() == null ? List.of() : body.roles();
        // SECURITY: reject reserved / bootstrap roles (superadmin + service roles) on this
        // indirect grant channel — the same boundary AdminController.grantRole enforces, which
        // a free-form OIDC default-role write would otherwise bypass (a brand ADMIN could seed
        // 'superadmin' here and self-escalate at first-login). Fail-closed BEFORE any DB write.
        String reserved = requested.stream().filter(ReservedRoles::isReserved).findFirst().orElse(null);
        if (reserved != null) {
            return Mono.error(ApiException.badRequest(
                    "role '" + reserved + "' is a reserved role and cannot be set as an OIDC "
                            + "default role (assignable only via the generator / Casdoor init_data seed)"));
        }
        return repo.replaceRoles(scope.domain(), providerKey, requested)
                .thenReturn(Map.<String, Object>of(
                        "provider", providerKey,
                        "roles", requested,
                        "domain", scope.domain()));
    }

    /**
     * Clear all default roles for an OIDC provider. Equivalent to
     * {@code PUT /{provider}/roles} with an empty roles list.
     */
    @PreAuthorize("hasRole('ADMIN')")
    @Operation(summary = "Clear provider roles", operationId = "oidcProviderRolesClearProviderRoles")
    @DeleteMapping("/{provider}/roles")
    public Mono<Void> clearProviderRoles(
            @PathVariable @Size(max = 64) @Pattern(regexp = "[A-Za-z0-9_-]+") String provider,
            Authentication auth) {
        PrincipalDomain scope = PrincipalDomain.of(auth, domainRegistry);
        return repo.clearRoles(scope.domain(), provider.toLowerCase());
    }
}
