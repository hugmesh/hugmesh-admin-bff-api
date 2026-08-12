package net.hugmesh.adminbff.servicecatalog;

import io.swagger.v3.oas.annotations.Operation;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;

import java.util.Map;

/**
 * Pre-flight seam for the App-Store superadmin UI: exposes whether the ArgoCD effector is
 * in real mode ({@code true}) or ships-dark / noop mode ({@code false}) so the UI can warn
 * before the superadmin triggers a provision.
 *
 * <h3>Authorization — SUPERADMIN-ONLY (defence-in-depth)</h3>
 * Mounted under {@code /bff/superadmin/**} (coarse gate in
 * {@link net.hugmesh.adminbff.config.SecurityConfig}) and additionally guarded by
 * {@code @PreAuthorize("hasRole('SUPERADMIN')")}. ADMIN / MOD / USER → 403.
 */
@RestController
@RequestMapping("/bff/superadmin/service-store")
public class ServiceCatalogEffectorController {

    private final AddServiceEffector effector;

    public ServiceCatalogEffectorController(AddServiceEffector effector) {
        this.effector = effector;
    }

    /**
     * Returns {@code {real: true}} when the injected {@link net.hugmesh.adminbff.argocd.ArgoCdClient}
     * is the real ArgoCD REST client, or {@code {real: false}} when the noop / ships-dark client
     * is active. The UI uses this for a pre-flight warning before calling provision.
     */
    @PreAuthorize("hasRole('SUPERADMIN')")
    @Operation(summary = "Effector mode: real ArgoCD client (true) or noop/dev (false).",
               operationId = "serviceCatalogEffectorMode")
    @GetMapping("/effector")
    public Mono<Map<String, Object>> effectorMode() {
        return Mono.just(Map.of("real", effector.isEffectorReal()));
    }
}
