package net.hugmesh.adminbff.notification;

import io.swagger.v3.oas.annotations.Operation;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * SUPERADMIN console for (re)provisioning the per-domain {@code @system} infra account —
 * the neutral notification sender (Notifications PR3). Provisioning is an INFRA op: it is
 * reachable ONLY by a SUPERADMIN, never by admin/mod/user.
 *
 * <h3>Authorization — SUPERADMIN-ONLY (defence-in-depth)</h3>
 * The coarse gate on {@code /bff/admin/**} ({@code SecurityConfig.commonRoutes}) is
 * {@code hasAnyRole('ADMIN','SUPERADMIN')}; this endpoint then adds
 * {@code @PreAuthorize("hasRole('SUPERADMIN')")}, so:
 * <ul>
 *   <li>SUPERADMIN — ALLOWED (re-provision is cross-domain infra; not domain-scoped).</li>
 *   <li>ADMIN — 403 (passes the coarse gate, walled at the per-method SUPERADMIN gate;
 *       provisioning the infra sender is above a brand admin).</li>
 *   <li>MOD / USER — 403 (never clear the coarse {@code hasAnyRole('ADMIN','SUPERADMIN')}
 *       gate at all).</li>
 * </ul>
 *
 * <h3>Idempotent re-provision</h3>
 * {@code POST /bff/admin/system-account/{domain}/provision} delegates to
 * {@link SystemAccountProvisioner#provision(String)} (which delegates to the idempotent
 * {@code CasdoorAdminClient.ensureUser}). Calling it repeatedly is a safe no-op — there
 * is no DELETE (the neutral sender is never torn down out from under live notifications).
 *
 * <h3>Ships dark</h3>
 * When {@code casdoor.admin.enabled=false} (the default) the provisioner has no Casdoor
 * client and {@link SystemAccountProvisioner#provision(String)} no-ops; the endpoint
 * still returns 200 with {@code provisioned:false} so the SUPERADMIN sees the gate is
 * closed rather than a server error.
 */
@RestController
@RequestMapping("/bff/admin/system-account")
@Validated
public class SystemAccountController {

    private static final Logger log = LoggerFactory.getLogger(SystemAccountController.class);

    private final SystemAccountProvisioner provisioner;

    public SystemAccountController(SystemAccountProvisioner provisioner) {
        this.provisioner = provisioner;
    }

    /** The Casdoor subject of the acting SUPERADMIN, for audit logging. */
    private static String subject(Authentication auth) {
        if (auth != null && auth.getPrincipal() instanceof Jwt jwt) {
            return jwt.getSubject();
        }
        return auth == null ? null : auth.getName();
    }

    /**
     * Idempotently (re)provision the {@code @system} account for {@code domain}.
     * SUPERADMIN-only. Returns the EXACT least-privilege role set that was ensured so the
     * caller can confirm no privileged role leaked.
     */
    @PreAuthorize("hasRole('SUPERADMIN')")
    @Operation(summary = "Provision", operationId = "systemAccountProvision")
    @PostMapping("/{domain}/provision")
    public Mono<Map<String, Object>> provision(
            @PathVariable @NotBlank @Size(max = 253) String domain,
            Authentication auth) {
        String actor = subject(auth);
        boolean enabled = provisioner.enabled();
        return provisioner.provision(domain)
                // Build the response after provisioning: log success + return summary fields.
                .then(Mono.fromSupplier(() -> buildProvisionResponse(actor, domain, enabled)));
    }

    /** Build the provision response map: log the action and return the summary fields. */
    private Map<String, Object> buildProvisionResponse(String actor, String domain, boolean enabled) {
        log.info("[system-account] superadmin {} (re)provisioned @system for domain '{}' (enabled={})",
                actor, domain, enabled);
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("domain", domain);
        out.put("handle", SystemAccountProvisioner.SYSTEM_HANDLE);
        out.put("email", SystemAccountProvisioner.systemEmail(domain));
        out.put("roles", SystemAccountProvisioner.SYSTEM_ROLES);
        // provisioned reflects whether a Casdoor write actually happened — false means SHIPS-DARK.
        out.put("provisioned", enabled);
        return out;
    }
}
