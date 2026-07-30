package systems.hugmesh.adminbff.servicecatalog;

import io.swagger.v3.oas.annotations.Operation;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import systems.hugmesh.commons.web.ApiException;
import systems.hugmesh.adminbff.web.dto.ProvisionServiceRequest;
import systems.hugmesh.adminbff.web.dto.ServiceDeploymentRequest;

/**
 * The SUPERADMIN App-Store DEPLOYMENT console — superadmin list / create / end of the
 * per-domain lifecycle accounting rows ({@code service_deployment}, schema 102). Creating a
 * deployment records {@code created_at} (now) + {@code ending_at} (the single expiry clock)
 * + {@code enforce_actions}; ending it CASes {@code active -> ended}. SHIPS DARK: no real
 * ArgoCD/Casdoor/cert effect — the enforce_actions are the recorded intent the later
 * effector resolves.
 *
 * <h3>Authorization — SUPERADMIN-ONLY (defence-in-depth)</h3>
 * Mounted under {@code /bff/superadmin/**} (coarse gate {@code hasRole('SUPERADMIN')} in
 * {@link systems.hugmesh.adminbff.config.SecurityConfig}); EVERY method ALSO carries
 * {@code @PreAuthorize("hasRole('SUPERADMIN')")}. ADMIN / MOD / USER → 403. The
 * {@code domain} is the explicit PATH target (the infra control plane picks the brand),
 * NEVER a body field. {@code created_by_subject} is stamped from the SUPERADMIN's
 * {@code jwt.getSubject()}.
 */
@RestController
@RequestMapping("/bff/superadmin/service-store/{domain}/deployments")
@Validated
public class ServiceDeploymentController {

    private final ServiceDeploymentService service;
    private final ServiceDeploymentRepository repo;
    private final AddServiceEffector effector;

    public ServiceDeploymentController(ServiceDeploymentService service,
                                       ServiceDeploymentRepository repo,
                                       AddServiceEffector effector) {
        this.service = service;
        this.repo = repo;
        this.effector = effector;
    }

    /** The Casdoor subject of the acting SUPERADMIN, from the validated JWT. */
    private static String subject(Authentication auth) {
        if (auth != null && auth.getPrincipal() instanceof Jwt jwt) {
            return jwt.getSubject();
        }
        return auth == null ? null : auth.getName();
    }

    // ── List the deployments for a {domain} (SUPERADMIN, explicit domain target) ──
    @PreAuthorize("hasRole('SUPERADMIN')")
    @Operation(summary = "List", operationId = "serviceDeploymentList")
    @GetMapping
    public Flux<ServiceDeployment> list(
            @PathVariable @NotBlank @Size(max = 253) String domain) {
        return service.listForDomain(domain);
    }

    // ── Create an ACTIVE deployment in a {domain} (SUPERADMIN) ───────────────────
    @PreAuthorize("hasRole('SUPERADMIN')")
    @Operation(summary = "Create", operationId = "serviceDeploymentCreate")
    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    public Mono<ServiceDeployment> create(
            @PathVariable @NotBlank @Size(max = 253) String domain,
            @Valid @RequestBody ServiceDeploymentRequest body,
            Authentication auth) {
        return service.create(domain, body.serviceKey(), body.profileRef(), body.endingAt(),
                body.enforceActions(), subject(auth));
    }

    // ── End a deployment by id (SUPERADMIN; CAS active->ended) ───────────────────
    @PreAuthorize("hasRole('SUPERADMIN')")
    @Operation(summary = "End", operationId = "serviceDeploymentEnd")
    @PostMapping("/{id}/end")
    public Mono<ServiceDeployment> end(
            @PathVariable @NotBlank @Size(max = 253) String domain,
            @PathVariable @NotBlank @Size(max = 36) String id) {
        return service.end(id);
    }

    /**
     * PROVISION an existing deployment (SUPERADMIN) — drive its accounting row through the
     * {@link AddServiceEffector}: per-service Casdoor role → route-access rule → ArgoCD
     * Application. SELECT/GIT sources provision (ships dark unless the effector is enabled);
     * DOCKERFILE/ZIP are guarded with a clear "requires the in-cluster builder" 400 until the
     * Kaniko builder (generator) exists. The {@code domain} of the loaded deployment must
     * match the path {@code domain} (the superadmin's explicit target).
     */
    @PreAuthorize("hasRole('SUPERADMIN')")
    @Operation(summary = "Provision", operationId = "serviceDeploymentProvision")
    @PostMapping("/{id}/provision")
    public Mono<ProvisionOutcome> provision(
            @PathVariable @NotBlank @Size(max = 253) String domain,
            @PathVariable @NotBlank @Size(max = 36) String id,
            @Valid @RequestBody ProvisionServiceRequest body) {
        return repo.findById(id)
                .switchIfEmpty(Mono.error(ApiException.notFound("no deployment '" + id + "'")))
                .flatMap(d -> provisionDeployment(d, domain, body));
    }

    /** Extract the deployment-domain guard + source construction into a named helper so the
     *  flatMap lambda stays within the Checkstyle LambdaBodyLength limit. */
    private Mono<ProvisionOutcome> provisionDeployment(ServiceDeployment d, String domain,
                                                        ProvisionServiceRequest body) {
        if (d.domain() != null && !d.domain().equals(domain)) {
            return Mono.error(ApiException.badRequest(
                    "deployment '" + d.id() + "' is not in domain '" + domain + "'"));
        }
        ServiceSource source = new ServiceSource(
                ServiceSource.kindOf(body.sourceKind()),
                body.repoUrl(), body.path(), body.targetRevision());
        return effector.provision(d, source)
                .map(ignored -> new ProvisionOutcome(d, effector.isEffectorReal()));
    }
}
