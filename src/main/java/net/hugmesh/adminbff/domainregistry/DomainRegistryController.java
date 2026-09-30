package net.hugmesh.adminbff.domainregistry;

import io.swagger.v3.oas.annotations.Operation;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import net.hugmesh.adminbff.web.dto.AllocateDomainRequest;
import net.hugmesh.adminbff.web.dto.CreateDomainRequest;
import net.hugmesh.adminbff.web.dto.DomainResponse;
import net.hugmesh.adminbff.web.dto.UpdateDomainRequest;

/**
 * The DOMAIN-REGISTRY SUPERADMIN console — runtime CRUD over {@code domain_registry}, the
 * source of truth for which brands/domains exist in the cluster (multi-tenancy PR9). The
 * runtime twin of the build-time {@code brands/domains.conf} the generator (#79) bakes
 * in; later PRs materialise these rows into a brand-list ArgoCD ApplicationSet. This
 * controller is the FOUNDATION: table + CRUD only — NO ApplicationSet / provisioning
 * effector here.
 *
 * <h3>Authorization — SUPERADMIN-ONLY, CROSS-DOMAIN (defence-in-depth)</h3>
 * The coarse gate on {@code /bff/admin/**} ({@code SecurityConfig.commonRoutes}) is
 * {@code hasAnyRole('ADMIN','SUPERADMIN')}. EVERY endpoint here then adds
 * {@code @PreAuthorize("hasRole('SUPERADMIN')")}, so:
 * <ul>
 *   <li>SUPERADMIN (the cross-domain infra super-role) — ALLOWED on list/get/create/
 *       update. It manages ALL domains, so these are deliberately NOT domain-scoped
 *       (no {@link net.hugmesh.commons.security.PrincipalDomain}); the registry IS
 *       the brand list.</li>
 *   <li>ADMIN — 403. It passes the coarse {@code /bff/admin/**} gate but is walled off
 *       at the per-method {@code hasRole('SUPERADMIN')} (provisioning brands is infra,
 *       above a brand admin).</li>
 *   <li>MOD / USER — 403. They never clear the coarse {@code hasAnyRole('ADMIN',
 *       'SUPERADMIN')} gate at all.</li>
 * </ul>
 * There is NO delete: a domain is SOFT-DISABLED via {@code PUT .../{domain}} with
 * {@code enabled:false} — a declarative registry never drops a live domain out from
 * under ArgoCD. {@code created_by_subject} is stamped from the SUPERADMIN's
 * {@code jwt.getSubject()}.
 */
@RestController
@RequestMapping("/bff/admin/domains")
@Validated
public class DomainRegistryController {

    private static final Logger log = LoggerFactory.getLogger(DomainRegistryController.class);

    private final DomainRegistryService service;
    private final DomainRegistryExportService export;

    public DomainRegistryController(DomainRegistryService service, DomainRegistryExportService export) {
        this.service = service;
        this.export = export;
    }

    /** The Casdoor subject of the acting SUPERADMIN, from the validated JWT. */
    private static String subject(Authentication auth) {
        if (auth != null && auth.getPrincipal() instanceof Jwt jwt) {
            return jwt.getSubject();
        }
        return auth == null ? null : auth.getName();
    }

    // ── List ALL registered domains (SUPERADMIN) ────────────────────────────────
    @PreAuthorize("hasRole('SUPERADMIN')")
    @Operation(summary = "List", operationId = "domainRegistryList")
    @GetMapping("")
    public Flux<DomainResponse> list() {
        return service.list().map(DomainResponse::of);
    }

    // ── Get one domain by its cluster_domain (SUPERADMIN) ───────────────────────
    @PreAuthorize("hasRole('SUPERADMIN')")
    @Operation(summary = "Get", operationId = "domainRegistryGet")
    @GetMapping("/{clusterDomain}")
    public Mono<DomainResponse> get(
            @PathVariable @NotBlank @Size(max = 253) String clusterDomain) {
        return service.get(clusterDomain).map(DomainResponse::of);
    }

    // ── Register a new domain (SUPERADMIN; created_by_subject from the JWT) ──────
    @PreAuthorize("hasRole('SUPERADMIN')")
    @Operation(summary = "Create", operationId = "domainRegistryCreate")
    @PostMapping("")
    @ResponseStatus(HttpStatus.CREATED)
    public Mono<DomainResponse> create(@Valid @RequestBody CreateDomainRequest body,
                                       Authentication auth) {
        String subject = subject(auth);
        return service.create(body, subject)
                .doOnNext(d -> log.info("[domain-registry] create cluster_domain={} by={}",
                        d.clusterDomain(), subject))
                .map(DomainResponse::of);
    }

    // ── Update / soft-disable an existing domain (SUPERADMIN) ───────────────────
    @PreAuthorize("hasRole('SUPERADMIN')")
    @Operation(summary = "Update", operationId = "domainRegistryUpdate")
    @PutMapping("/{clusterDomain}")
    public Mono<DomainResponse> update(
            @PathVariable @NotBlank @Size(max = 253) String clusterDomain,
            @Valid @RequestBody UpdateDomainRequest body) {
        return service.update(clusterDomain, body).map(DomainResponse::of);
    }

    // ── Allocate now (SUPERADMIN; decision 89c — repair a pre-decision-29 row) ───────
    /**
     * Give a domain registered before decision 29 what it lacks to be provisionable: its MCS
     * category pair (from the allocator, never from the caller) and, when it has none, its slug
     * (from the body, set ONCE). 409 when the row already has both, when the body names a slug
     * different from the stored one, or when the slug is taken; 400 for an invalid slug or a
     * missing one on a slug-less row; 404 for an unknown domain. Audited by an
     * {@code [domain-registry] AUDIT allocate-now} log line naming the actor.
     */
    @PreAuthorize("hasRole('SUPERADMIN')")
    @Operation(summary = "Allocate now", operationId = "domainRegistryAllocateNow")
    @PostMapping("/{clusterDomain}/allocate")
    public Mono<DomainResponse> allocateNow(
            @PathVariable @NotBlank @Size(max = 253) String clusterDomain,
            @Valid @RequestBody(required = false) AllocateDomainRequest body,
            Authentication auth) {
        return service.allocateNow(clusterDomain, body == null ? null : body.nsPrefix(),
                        subject(auth))
                .map(DomainResponse::of);
    }

    // ── Provisioning STATUS read (SUPERADMIN; "registered but not yet provisioned") ──
    /**
     * The provisioning-status read the admin-ui Domains console renders the
     * "registered but not yet provisioned" chip from (the platform-capability-gating
     * mandate). The SAME {@link DomainResponse} rows the list returns, carrying the band-190
     * {@code caProvisioned} / {@code appsetRegistered} / {@code lastReconciledGeneration}
     * fields (DEFAULT {@code false}/{@code false}/{@code 0} until the later generator
     * domain-reconcile effector flips them — so at defaults every domain reads unprovisioned).
     * A thin read alias of {@code GET ""}: SUPERADMIN-only (a domain's provisioning state is
     * cross-domain infra), never domain-scoped.
     */
    @PreAuthorize("hasRole('SUPERADMIN')")
    @Operation(summary = "Status", operationId = "domainRegistryStatus")
    @GetMapping("/status")
    public Flux<DomainResponse> status() {
        return service.list().map(DomainResponse::of);
    }

    // ── Signed cross-domain export (SUPERADMIN | internal mTLS) ─────────────────
    /**
     * The signed {@code domain_registry} export the (not-yet-built) generator
     * DOMAIN-RECONCILE agent consumes — the ONE missing export symmetry for runtime
     * add-domain provisioning (the device-license, egress-VPN and node-storage registries
     * each already ship a signed {@code /export}; this adds it for domains). The signed body
     * carries EVERY ENABLED domain (the registry is the cross-domain brand list — there is
     * nothing per-node to scope to, unlike the device/VPN exports), each entry the descriptors
     * the agent materialises into the per-domain CA loop + the brand-list ArgoCD
     * ApplicationSet, plus the band-190 provisioning-status the agent reconciles against. The
     * {@code caRef} is a CA *reference*, NEVER the cert/key bytes — secrets stay off-export.
     * Canonical line-oriented bytes + detached Ed25519 + monotonic generation; the agent
     * verifies against the BAKED key-USB public half and fail-closes (keeps last-good) on an
     * unsigned/tampered/rolled-back payload. An EMPTY registry yields an EMPTY signed body
     * (fail-closed, never a leaky error).
     *
     * <p>Same {@code SUPERADMIN | internal-mTLS} gate as the device-license export
     * ({@code @PreAuthorize("hasRole('SUPERADMIN')")} AND served only over the in-cluster
     * mTLS transport in the deployment; no ROLE_USER/ROLE_ADMIN principal reaches it — the
     * reconcile agent presents the SUPERADMIN service identity over mTLS). The optional
     * {@code node} fingerprint is pinned into the export header as PROVENANCE only (it does
     * NOT scope the cross-domain body).
     *
     * <p>DECISION 89b = A: a node agent does NOT call this route — it holds the shared
     * {@code X-Internal-Token}, which grants {@code ROLE_SERVICE} and never SUPERADMIN. It fetches
     * the byte-identical mirror {@code GET /bff/internal/domains/export}
     * ({@link DomainRegistryInternalController}). This SUPERADMIN route stays for the console.
     */
    @PreAuthorize("hasRole('SUPERADMIN')")
    @Operation(summary = "Export", operationId = "domainRegistryExport")
    @GetMapping("/export")
    public Mono<DomainExportModels.SignedDomainExport> export(
            @RequestParam(value = "node", required = false) @Size(max = 128) String node) {
        return export.exportRegistry(node);
    }
}
