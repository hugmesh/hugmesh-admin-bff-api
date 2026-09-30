package net.hugmesh.adminbff.oidcprovider;

import io.swagger.v3.oas.annotations.Operation;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import java.util.ArrayList;
import java.util.Collections;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;
import net.hugmesh.authcore.casdoor.CasdoorAdminClient;

import java.util.List;
import java.util.Locale;

/**
 * Applies the admin-configured OIDC DEFAULT-ROLE map to a first-seen OIDC user — the
 * "apply" half of the default-role registration hook (the "probe" half is the
 * scheduled poll in hugmesh-actions {@code OidcDefaultRoleProbeAction}, which detects
 * newly-created Casdoor users and calls this endpoint once per genuinely-new user).
 *
 * <p>The stored map ({@code oidc_provider_default_roles}, written by admins via
 * {@link OidcProviderRolesController}) lists, per {@code (domain, provider)}, the role
 * names a brand-new user of that provider should receive. This endpoint reads that map
 * ({@link OidcProviderRoleRepository#rolesFor}) and ADDS each role to the (already Casdoor-
 * created) user via the shared {@link CasdoorAdminClient}.
 *
 * <h3>SECURITY — mTLS, NO JWT, internal-token guarded</h3>
 * Lives under {@code /bff/internal/**}, which {@code SecurityConfig} gates to
 * {@code ROLE_SERVICE} — the actions probe satisfies it with the in-cluster
 * {@code X-Internal-Token} (promoted to a SERVICE principal), on top of the mTLS transport and
 * the constant-time check in auth-core's {@code InternalTokenWebFilter} — the same surface as
 * the other {@code /bff/internal} controllers (e.g. {@code DeviceEnrollmentController},
 * {@code InternalAccountController}). It takes NO human JWT and has NO {@code @PreAuthorize}.
 *
 * <h3>Fail-closed + additive-only + dark-by-default</h3>
 * <ul>
 *   <li><b>Dark by default.</b> The Casdoor admin client is {@code @Nullable} and is
 *       {@code null} unless {@code casdoor.admin.enabled=true}. When null this endpoint is
 *       a DRY-RUN: it resolves the map (and logs what it WOULD apply) but writes nothing,
 *       returning {@code assignedRoles:[]}. The caller in actions is itself
 *       {@code @ConditionalOnProperty}-gated off by default, so the whole loop ships inert.</li>
 *   <li><b>Additive only.</b> It only ever ADDs roles from the stored default-role floor —
 *       never removes, overwrites, or escalates beyond the configured set.
 *       {@link CasdoorAdminClient#addUserToRole} is itself idempotent (Casdoor dedups role
 *       members), so a repeat call (pod restart within the caller's lookback window) is a
 *       no-op — first-seen-ness is the CALLER's responsibility, not this endpoint's.</li>
 *   <li><b>Per-role error isolation.</b> One role that fails to apply (e.g. a Casdoor role
 *       that does not exist) is logged and skipped; the remaining roles still apply, and
 *       only the successfully-applied roles are reported.</li>
 * </ul>
 */
@RestController
@RequestMapping("/bff/internal/oidc")
@Validated
public class OidcFirstLoginController {

    private static final Logger log = LoggerFactory.getLogger(OidcFirstLoginController.class);

    private final OidcProviderRoleRepository roles;

    /** The Casdoor admin client — {@code null} (dry-run) unless {@code casdoor.admin.enabled=true}. */
    @Nullable
    private final CasdoorAdminClient casdoor;

    public OidcFirstLoginController(OidcProviderRoleRepository roles,
                                    @Nullable CasdoorAdminClient casdoor) {
        this.roles = roles;
        this.casdoor = casdoor;
    }

    /**
     * The first-login apply request. {@code casdoorUsername} is the username of the
     * already-created Casdoor user (resolved by the actions probe from Casdoor's
     * newest-users list); {@code domain} + {@code provider} key the stored default-role map.
     */
    public record FirstLoginRequest(
            @NotBlank(message = "domain is required") @Size(max = 200) String domain,
            @NotBlank(message = "provider is required") @Size(max = 200) String provider,
            @NotBlank(message = "casdoorUsername is required") @Size(max = 400) String casdoorUsername) {
    }

    /**
     * The result. {@code assignedRoles} are the roles ACTUALLY applied to Casdoor (empty on
     * a dry-run or an empty map). The field name matches the actions-side {@code FirstLoginResponse}
     * DTO contract, so the JSON is {@code {"assignedRoles":[...]}}.
     */
    public record FirstLoginResponse(List<String> assignedRoles) {

        public FirstLoginResponse {
            assignedRoles = assignedRoles == null ? null : Collections.unmodifiableList(new ArrayList<>(assignedRoles));
        }
    }

    /**
     * Resolve + apply the default-role map for a first-seen OIDC user.
     *
     * @param body the {@code (domain, provider, casdoorUsername)} tuple
     * @return the roles actually applied to Casdoor (empty on dry-run / empty map)
     */
    @Operation(summary = "Apply OIDC default roles to a first-seen user",
            operationId = "oidcFirstLoginApplyDefaultRoles")
    @PostMapping("/first-login")
    public Mono<FirstLoginResponse> firstLogin(@Valid @RequestBody FirstLoginRequest body) {
        String provider = body.provider().toLowerCase(Locale.ROOT);

        // Dry-run: Casdoor admin disabled (the dark default). Resolve the map so the read
        // path is exercised and log what WOULD be applied, but write nothing and report [].
        if (casdoor == null) {
            return roles.rolesFor(body.domain(), provider)
                    .collectList()
                    .doOnNext(would -> log.info(
                            "[oidc-first-login] DRY-RUN (casdoor.admin disabled) — would apply {} to "
                                    + "user={} domain={} provider={}",
                            would, body.casdoorUsername(), body.domain(), provider))
                    .thenReturn(new FirstLoginResponse(List.of()));
        }

        String userRef = casdoor.organization() + "/" + body.casdoorUsername();
        return roles.rolesFor(body.domain(), provider)
                // SECURITY (defense-in-depth): never APPLY a reserved / bootstrap role even if a
                // stale or seeded row carries one. The write path (OidcProviderRolesController)
                // already blocks these, but a row predating that guard — or a direct DB seed —
                // must still be skipped here so the first-login hook can never grant superadmin /
                // a service role. Mirrors AdminController.grantRole's non-grantable boundary.
                .filter(roleName -> {
                    boolean reserved = ReservedRoles.isReserved(roleName);
                    if (reserved) {
                        log.warn("[oidc-first-login] SKIPPING reserved default role {} for {} "
                                + "(not grantable via OIDC default-role channel)", roleName, userRef);
                    }
                    return !reserved;
                })
                // Apply in stored order; isolate per-role failures so one bad role does not
                // abort the rest. Collect only the roles that actually applied.
                .concatMap(roleName -> casdoor.addUserToRole(casdoorRoleName(roleName), userRef)
                        .thenReturn(roleName)
                        .onErrorResume(err -> {
                            log.warn("[oidc-first-login] failed to apply default role {} to {} — skipping: {}",
                                    roleName, userRef, err.toString());
                            return Mono.empty();
                        }))
                .collectList()
                .map(FirstLoginResponse::new)
                .doOnNext(resp -> log.info(
                        "[oidc-first-login] applied {} to user={} domain={} provider={}",
                        resp.assignedRoles(), body.casdoorUsername(), body.domain(), provider));
    }

    /**
     * Map a stored default-role name to the Casdoor role name {@link CasdoorAdminClient#addUserToRole}
     * expects. The admin UI stores LOWERCASE short names ({@code [a-z0-9_-]+}, e.g. {@code user},
     * {@code mod}, {@code games_admin}), but the Casdoor roles in this org are {@code ROLE_}-prefixed
     * upper-case (the same names {@code AdminController.grantRole} passes to {@code addUserToRole},
     * e.g. {@code ROLE_USER}, {@code ROLE_GAMES_ADMIN}). So we prefix + upper-case, normalising any
     * hyphen to an underscore to match the {@code ROLE_<UNDERSCORED>} convention.
     *
     * <p>If a stored name maps to a Casdoor role that does not exist, {@code addUserToRole} fails
     * for that one role and it is skipped (per-role isolation above) — fail-safe (under-grant),
     * never an over-grant. NOTE: the lowercase→{@code ROLE_} convention is the single point to
     * revisit if a brand uses a different Casdoor role-name scheme.
     */
    private static String casdoorRoleName(String stored) {
        return "ROLE_" + stored.trim().toUpperCase(Locale.ROOT).replace('-', '_');
    }
}
