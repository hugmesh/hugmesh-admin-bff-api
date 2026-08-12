package net.hugmesh.adminbff.servicecatalog;

import io.swagger.v3.oas.annotations.Operation;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import org.springframework.http.ContentDisposition;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.bind.annotation.CookieValue;
import reactor.core.publisher.Mono;
import net.hugmesh.authcore.casdoor.MfaStepUpService;
import net.hugmesh.authcore.config.SessionCookieWebFilter;
import net.hugmesh.commons.web.ApiException;
import net.hugmesh.adminbff.servicecatalog.federation.ServiceCatalogFederationService;
import net.hugmesh.adminbff.servicecatalog.scaffold.ScaffoldArchetype;
import net.hugmesh.adminbff.servicecatalog.scaffold.ScaffoldService;
import net.hugmesh.adminbff.servicecatalog.scaffold.ServiceScaffold;
import net.hugmesh.adminbff.web.dto.FederateServiceRequest;
import net.hugmesh.adminbff.web.dto.ScaffoldServiceRequest;

import java.util.List;
import java.util.Map;

/**
 * The SUPERADMIN Service-Store WIZARD backend — the "scaffold a new service, then federate it"
 * surface of the App-Store, sibling of {@link ServiceDeploymentController} (the deployment
 * accounting rows) and {@link ServiceCatalogEffectorController} (the ArgoCD effector pre-flight).
 *
 * <h3>Endpoints (all under {@code /bff/superadmin/service-store})</h3>
 * <ul>
 *   <li>{@code GET  /scaffold/archetypes} — the embedded scaffold catalog (read).</li>
 *   <li>{@code POST /{domain}/scaffold} — request a scaffold for a brand (STEP-UP; 201).</li>
 *   <li>{@code GET  /{domain}/scaffold/{id}/archive} — the rendered starter codebase ZIP (read).</li>
 *   <li>{@code POST /{domain}/deployments/{id}/federate} — federate a deployment's UI (STEP-UP).</li>
 *   <li>{@code GET  /federation} — the federate-leg status (read).</li>
 * </ul>
 *
 * <h3>Authorization — SUPERADMIN-ONLY (defence-in-depth)</h3>
 * Mounted under {@code /bff/superadmin/**} (coarse gate {@code hasRole('SUPERADMIN')} in
 * {@link net.hugmesh.adminbff.config.SecurityConfig}); EVERY method ALSO carries
 * {@code @PreAuthorize("hasRole('SUPERADMIN')")}. ADMIN / MOD / USER → 403. The {@code domain} is
 * the explicit PATH target (never a body field). ON TOP of the role gate, the two MUTATING verbs
 * (scaffold create, federate) additionally require a valid {@code X-ServiceStore-StepUp} token
 * ({@link ServiceStoreStepUpGate}, A5-unified with a fresh Casdoor-MFA stamp) — the deliberate
 * re-confirm the platform requires for privileged infra writes.
 *
 * <h3>Ships dark where it must</h3>
 * Scaffolding is DATA/INTENT + an on-demand render (no deploy). Federating goes through the
 * {@link ServiceCatalogFederationService}, whose {@code FederationModuleClient} is a no-op unless
 * {@code app.appstore.federation.enabled=true} — so the outcome reports {@code federationReal}
 * honestly, and {@code gitopsDescriptorPending} stays true (the GitOps descriptor automation does
 * not exist yet).
 */
@RestController
@RequestMapping("/bff/superadmin/service-store")
@Validated
public class ServiceStoreWizardController {

    private static final int MAX_ID = 36;

    private final ScaffoldService scaffold;
    private final ServiceDeploymentRepository deployments;
    private final ServiceCatalogFederationService federation;
    private final ServiceStoreStepUpGate stepUp;
    private final MfaStepUpService mfaStepUp;

    public ServiceStoreWizardController(ScaffoldService scaffold,
                                        ServiceDeploymentRepository deployments,
                                        ServiceCatalogFederationService federation,
                                        ServiceStoreStepUpGate stepUp,
                                        MfaStepUpService mfaStepUp) {
        this.scaffold = scaffold;
        this.deployments = deployments;
        this.federation = federation;
        this.stepUp = stepUp;
        this.mfaStepUp = mfaStepUp;
    }

    private static String subject(Authentication auth) {
        if (auth != null && auth.getPrincipal() instanceof Jwt jwt) {
            return jwt.getSubject();
        }
        return auth == null ? null : auth.getName();
    }

    // ── scaffold catalog (read) ──────────────────────────────────────────────────
    @PreAuthorize("hasRole('SUPERADMIN')")
    @Operation(summary = "Scaffold archetypes", operationId = "serviceScaffoldArchetypes")
    @GetMapping("/scaffold/archetypes")
    public Mono<List<ScaffoldArchetype>> archetypes() {
        return Mono.just(scaffold.archetypes());
    }

    // ── request a scaffold (mutating; step-up; 201) ──────────────────────────────
    @PreAuthorize("hasRole('SUPERADMIN')")
    @Operation(summary = "Create scaffold", operationId = "serviceScaffoldCreate")
    @PostMapping("/{domain}/scaffold")
    @ResponseStatus(HttpStatus.CREATED)
    public Mono<ServiceScaffold> createScaffold(
            @PathVariable @NotBlank @Size(max = 253) String domain,
            @Valid @RequestBody ScaffoldServiceRequest body,
            @RequestHeader(value = ServiceStoreStepUpGate.STEP_UP_HEADER, required = false) String stepUpToken,
            @CookieValue(name = SessionCookieWebFilter.SESSION_COOKIE, required = false) String sessionCookie,
            @RequestHeader(name = HttpHeaders.AUTHORIZATION, required = false) String authHeader,
            Authentication auth) {
        String actor = subject(auth);
        if (actor == null || actor.isBlank()) {
            return Mono.error(ApiException.unauthorized("no subject on token"));
        }
        String sessionToken = SessionCookieWebFilter.bffTokenFrom(sessionCookie, authHeader);
        return mfaStepUp.isFresh(sessionToken)
                .flatMap(mfaFresh -> createIfStepUpSatisfied(mfaFresh, actor, stepUpToken, sessionToken,
                        domain, body));
    }

    private Mono<ServiceScaffold> createIfStepUpSatisfied(boolean mfaFresh, String actor,
            String stepUpToken, String sessionToken, String domain, ScaffoldServiceRequest body) {
        if (!stepUp.isSatisfied(actor, stepUpToken, mfaFresh)) {
            return Mono.error(ApiException.forbidden(
                    "scaffolding a service requires step-up re-authentication (present "
                    + ServiceStoreStepUpGate.STEP_UP_HEADER + ")"));
        }
        Mono<Void> consume = mfaFresh ? mfaStepUp.consume(sessionToken) : Mono.empty();
        return consume.then(scaffold.create(domain, body.serviceKey(), body.archetype(),
                body.displayName(), body.mountAt(), body.requiresRole(), actor));
    }

    // ── rendered starter codebase (read; application/zip) ────────────────────────
    /**
     * The rendered starter codebase ZIP for a scaffold (SUPERADMIN; the {@code domain} is the
     * explicit target). Reads only existing columns + the embedded skeleton; the first successful
     * render CASes the row {@code requested -> archived} (idempotent). A 404 when no such scaffold
     * exists; a 400 when it is not in the path {@code domain}.
     */
    @PreAuthorize("hasRole('SUPERADMIN')")
    @Operation(summary = "Scaffold archive", operationId = "serviceScaffoldArchive")
    @GetMapping(value = "/{domain}/scaffold/{id}/archive", produces = "application/zip")
    public Mono<ResponseEntity<byte[]>> scaffoldArchive(
            @PathVariable @NotBlank @Size(max = 253) String domain,
            @PathVariable @NotBlank @Size(max = MAX_ID) String id) {
        return scaffold.archive(domain, id).map(bytes -> ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_DISPOSITION, ContentDisposition.attachment()
                        .filename(id + "-scaffold.zip").build().toString())
                .contentType(MediaType.parseMediaType("application/zip"))
                .body(bytes));
    }

    // ── federate a deployment's UI (mutating; step-up) ───────────────────────────
    @PreAuthorize("hasRole('SUPERADMIN')")
    @Operation(summary = "Federate deployment", operationId = "serviceDeploymentFederate")
    @PostMapping("/{domain}/deployments/{id}/federate")
    public Mono<FederateOutcome> federate(
            @PathVariable @NotBlank @Size(max = 253) String domain,
            @PathVariable @NotBlank @Size(max = MAX_ID) String id,
            @Valid @RequestBody FederateServiceRequest body,
            @RequestHeader(value = ServiceStoreStepUpGate.STEP_UP_HEADER, required = false) String stepUpToken,
            @CookieValue(name = SessionCookieWebFilter.SESSION_COOKIE, required = false) String sessionCookie,
            @RequestHeader(name = HttpHeaders.AUTHORIZATION, required = false) String authHeader,
            Authentication auth) {
        String actor = subject(auth);
        if (actor == null || actor.isBlank()) {
            return Mono.error(ApiException.unauthorized("no subject on token"));
        }
        String sessionToken = SessionCookieWebFilter.bffTokenFrom(sessionCookie, authHeader);
        return mfaStepUp.isFresh(sessionToken)
                .flatMap(mfaFresh -> federateIfStepUpSatisfied(mfaFresh, actor, stepUpToken, sessionToken,
                        domain, id, body));
    }

    private Mono<FederateOutcome> federateIfStepUpSatisfied(boolean mfaFresh, String actor,
            String stepUpToken, String sessionToken, String domain, String id, FederateServiceRequest body) {
        if (!stepUp.isSatisfied(actor, stepUpToken, mfaFresh)) {
            return Mono.error(ApiException.forbidden(
                    "federating a deployment requires step-up re-authentication (present "
                    + ServiceStoreStepUpGate.STEP_UP_HEADER + ")"));
        }
        Mono<Void> consume = mfaFresh ? mfaStepUp.consume(sessionToken) : Mono.empty();
        return consume.then(deployments.findById(id)
                .switchIfEmpty(Mono.error(ApiException.notFound("no deployment '" + id + "'")))
                .flatMap(d -> federateDeployment(d, domain, body)));
    }

    /** Domain-guard the loaded deployment (the superadmin's explicit target, mirroring provision)
     *  then drive the federate leg. */
    private Mono<FederateOutcome> federateDeployment(ServiceDeployment d, String domain,
                                                     FederateServiceRequest body) {
        if (d.domain() != null && !d.domain().equals(domain)) {
            return Mono.error(ApiException.badRequest(
                    "deployment '" + d.id() + "' is not in domain '" + domain + "'"));
        }
        return federation.federate(d, body);
    }

    // ── federate-leg status (read) ───────────────────────────────────────────────
    @PreAuthorize("hasRole('SUPERADMIN')")
    @Operation(summary = "Federation status", operationId = "serviceCatalogFederationStatus")
    @GetMapping("/federation")
    public Mono<Map<String, Object>> federationStatus() {
        return Mono.just(federation.status());
    }
}
