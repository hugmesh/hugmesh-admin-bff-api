package net.hugmesh.adminbff.servicecatalog;

import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;
import net.hugmesh.adminbff.argocd.ArgoCdClient;
import net.hugmesh.adminbff.routeaccess.RouteAccessService;
import net.hugmesh.adminbff.routeaccess.RouteRule;
import net.hugmesh.adminbff.servicecatalog.repourl.RepoUrlValidator;
import net.hugmesh.authcore.casdoor.CasdoorAdminClient;
import net.hugmesh.commons.web.ApiException;

import java.util.Set;

/**
 * The App-Store {@code AddService} EFFECTOR — drives an existing {@code service_deployment}
 * row (PR1 data layer) from accounting-only into a REAL provisioned service: per-service
 * Casdoor role → per-service route-access rule(s) → ArgoCD {@code Application}. The reverse
 * (teardown at end-of-lease) revokes them in the opposite order.
 *
 * <h3>Ships DARK by default</h3>
 * The ArgoCD leg is gated by {@code app.appstore.effector.enabled}: when false (the DEFAULT)
 * the injected {@link ArgoCdClient} is the {@link net.hugmesh.adminbff.argocd.NoopArgoCdClient}
 * (no ArgoCD call) — the effector still runs its full sequence so it is unit-testable, but
 * makes NO real ArgoCD mutation. The Casdoor leg is likewise gated by
 * {@code casdoor.admin.enabled} (a null {@link CasdoorAdminClient} → the role step is skipped).
 *
 * <h3>Source coverage (the V2 fork)</h3>
 * SELECT + GIT reference a PRE-BUILT image / existing repo and provision TODAY. DOCKERFILE +
 * ZIP need an image BUILT first by the in-cluster Kaniko builder (the generator PR) — there
 * is no builder yet, so those sources are GUARDED with a clear "requires in-cluster builder"
 * error rather than half-deploying an Application that points at a non-existent image.
 *
 * <h3>Ordering (the V7 note)</h3>
 * The Casdoor role is created BEFORE the route-access rule that references it, and both
 * BEFORE the ArgoCD Application; teardown reverses (delete Application → revoke route rule →
 * delete role). Each leg is idempotent so a re-run / retry is safe.
 */
@Service
public class AddServiceEffector {

    private static final Logger log = LoggerFactory.getLogger(AddServiceEffector.class);

    /** The per-brand external gateway a new service's route-access rule is scoped to. The
     *  superadmin curates per-domain; the gateway name follows the per-domain be-gateway
     *  convention. Superadmin/tailnet-only services are NOT given a public be-gateway rule
     *  (that is the generator's tailnet superadmin-gateway leg). */
    private final ArgoCdClient argoCd;
    @Nullable
    private final CasdoorAdminClient casdoor;
    private final RouteAccessService routeAccess;
    /** Optional: wired only when {@code app.appstore.builder.enabled=true}. When null,
     *  DOCKERFILE/ZIP sources are rejected with a 400 (the pre-builder guard). */
    @Nullable
    private final KanikoBuildLauncher builder;
    /** Optional host allowlist for the source repo URL — mirrors {@link KanikoBuildLauncher}'s
     *  {@code app.appstore.repo-host-allowlist} so the LIVE (SELECT/GIT) provision path applies
     *  the SAME structural SSRF guard the (DOCKERFILE/ZIP) build path already does; empty = any
     *  valid host. */
    private final Set<String> repoHostAllowlist;

    @org.springframework.beans.factory.annotation.Autowired
    public AddServiceEffector(ArgoCdClient argoCd,
                              @Nullable CasdoorAdminClient casdoor,
                              RouteAccessService routeAccess,
                              @Nullable KanikoBuildLauncher builder,
                              @Value("${app.appstore.repo-host-allowlist:}") String repoHostAllowlistCsv) {
        this.argoCd = argoCd;
        this.casdoor = casdoor;
        this.routeAccess = routeAccess;
        this.builder = builder;
        this.repoHostAllowlist = RepoUrlValidator.parseHostAllowlist(repoHostAllowlistCsv);
    }

    /** Convenience constructor with NO host allowlist (any well-formed, allowed-scheme,
     *  non-empty-host repo URL is accepted) — the structural scheme/host SSRF guards still run.
     *  Used by tests / wirings that do not configure {@code app.appstore.repo-host-allowlist}. */
    public AddServiceEffector(ArgoCdClient argoCd,
                              @Nullable CasdoorAdminClient casdoor,
                              RouteAccessService routeAccess,
                              @Nullable KanikoBuildLauncher builder) {
        this(argoCd, casdoor, routeAccess, builder, "");
    }

    /** True when the ArgoCD leg would make a real mutation (the effector is enabled). A
     *  ships-dark test asserts this is false by default. */
    public boolean effectorEnabled() {
        return argoCd.isReal();
    }

    /** Alias for {@link #effectorEnabled()} — the controller/API seam name exposed via
     *  GET /bff/superadmin/service-store/effector → {@code {real: boolean}}. */
    public boolean isEffectorReal() {
        return argoCd.isReal();
    }

    /**
     * PROVISION the service described by {@code deployment} from {@code source}. SELECT/GIT
     * run the full create sequence; DOCKERFILE/ZIP are rejected until the Kaniko builder
     * exists. Returns the created ArgoCD Application name on success.
     *
     * <ol>
     *   <li>ensure the per-service Casdoor role (idempotent create) — skipped if no Casdoor
     *       client is wired;</li>
     *   <li>add the per-service route-access rule (role → the service's URL pattern) scoped
     *       to the deployment's brand;</li>
     *   <li>create the ArgoCD Application that registers the descriptor repo (ships dark
     *       unless the effector is enabled).</li>
     * </ol>
     */
    public Mono<String> provision(ServiceDeployment deployment, ServiceSource source) {
        if (deployment == null || source == null) {
            return Mono.error(ApiException.badRequest("deployment and source are required"));
        }
        if (source.kind().requiresBuilder() && builder == null) {
            // DOCKERFILE / ZIP: no in-cluster builder wired — guard with a clear message.
            return Mono.error(ApiException.badRequest(
                    "service source " + source.kind() + " requires the in-cluster image builder "
                            + "(Kaniko) which is not yet available; use SELECT (catalog) or GIT "
                            + "(prebuilt repo) sources, or enable the builder"));
        }
        if (source.repoUrl() == null || source.repoUrl().isBlank()) {
            return Mono.error(ApiException.badRequest("source repoUrl is required for "
                    + source.kind() + " (the descriptor/GitOps repo ArgoCD watches)"));
        }
        // LAYER 2 (symmetric SSRF guard on the LIVE path, PR #176 verify recommendation): re-run
        // the SAME structural RepoUrlValidator (with the SAME configurable host-allowlist the
        // KanikoBuildLauncher build path uses) BEFORE argoCd.createApplication(). The request DTO
        // (@RepoUrl on ProvisionServiceRequest) already rejects a hostile repoUrl with a 400, but an
        // internal / non-controller caller can reach provision() directly with an unvalidated URL —
        // on the SELECT/GIT path that URL would flow straight to ArgoCD with no structural re-check.
        // Re-validating HERE fails CLOSED (same 400 ApiException thrown elsewhere) so a
        // file:///etc/passwd / http://169.254.169.254/... metadata-SSRF / host-less git:// URL never
        // reaches argoCd.createApplication(). This mirrors the sink backstop in KanikoBuildLauncher.
        RepoUrlValidator.Result repoCheck = RepoUrlValidator.validate(source.repoUrl(), repoHostAllowlist);
        if (!repoCheck.valid()) {
            return Mono.error(ApiException.badRequest("invalid source repoUrl: " + repoCheck.reason()));
        }
        PerServiceIdentity identity = new PerServiceIdentity(deployment.domain(), deployment.serviceKey());
        String appName = identity.vaultPkiRole();   // <domain>-<service>, the Application name

        if (source.kind().requiresBuilder()) {
            // DOCKERFILE (or ZIP): builder is non-null here (checked above). Run the full
            // create sequence: role → route rule → Kaniko build → ArgoCD Application.
            // builder.build() returns the pushed image ref; .then() ignores the value because
            // ArgoCD points at the git repo, not the image ref directly.
            return ensureRole(identity)
                    .then(addRouteRule(deployment, identity))
                    .then(builder.build(deployment.domain(), deployment.serviceKey(), source))
                    .then(argoCd.createApplication(appName, source.repoUrl(), source.path(),
                            source.targetRevision(), identity.destNamespace()))
                    .doOnSuccess(name -> log.info(
                            "[appstore-effector] provisioned {} in {} via Kaniko build "
                                    + "(app='{}', role='{}', enabled={})",
                            deployment.serviceKey(), deployment.domain(), name, identity.casdoorRole(),
                            effectorEnabled()));
        }

        // SELECT / GIT: pre-built image — no build step, go straight to ArgoCD.
        return ensureRole(identity)
                .then(addRouteRule(deployment, identity))
                .then(argoCd.createApplication(appName, source.repoUrl(), source.path(),
                        source.targetRevision(), identity.destNamespace()))
                .doOnSuccess(name -> log.info(
                        "[appstore-effector] provisioned {} in {} (app='{}', role='{}', enabled={})",
                        deployment.serviceKey(), deployment.domain(), name, identity.casdoorRole(),
                        effectorEnabled()));
    }

    /**
     * TEARDOWN the service for an ENDED {@code deployment} — the reverse of {@link #provision}:
     * delete the ArgoCD Application, revoke the route-access rule, delete the Casdoor role.
     * Each leg tolerates already-absent (idempotent). This is the real effect the App-Store
     * expiry loop emits via {@link EnforceActionEmitter} once the effector is enabled.
     */
    public Mono<Void> teardown(ServiceDeployment deployment) {
        if (deployment == null) {
            return Mono.empty();
        }
        PerServiceIdentity identity = new PerServiceIdentity(deployment.domain(), deployment.serviceKey());
        String appName = identity.vaultPkiRole();
        return argoCd.deleteApplication(appName)
                .then(removeRouteRules(deployment, identity))
                .then(deleteRole(identity))
                .doOnSuccess(v -> log.info(
                        "[appstore-effector] tore down {} in {} (app='{}', role='{}', enabled={})",
                        deployment.serviceKey(), deployment.domain(), appName, identity.casdoorRole(),
                        effectorEnabled()))
                .then();
    }

    // ── Legs ─────────────────────────────────────────────────────────────
    private Mono<Void> ensureRole(PerServiceIdentity identity) {
        if (casdoor == null) {
            log.debug("[appstore-effector] no Casdoor admin client wired — role '{}' step skipped",
                    identity.casdoorRole());
            return Mono.empty();
        }
        return casdoor.createRole(identity.casdoorRole());
    }

    private Mono<Void> deleteRole(PerServiceIdentity identity) {
        if (casdoor == null) {
            return Mono.empty();
        }
        return casdoor.deleteRole(identity.casdoorRole());
    }

    /** The route-access rule: the service's Casdoor role may reach the service's URL pattern
     *  from the per-domain be-gateway, scoped to the deployment's brand. */
    private Mono<Void> addRouteRule(ServiceDeployment deployment, PerServiceIdentity identity) {
        RouteRule rule = new RouteRule(
                null,
                identity.domainSlugGateway(),
                identity.urlPattern(),
                identity.casdoorRole(),
                null,
                true,
                deployment.domain());
        return routeAccess.add(rule).then();
    }

    private Mono<Void> removeRouteRules(ServiceDeployment deployment, PerServiceIdentity identity) {
        // Internal SYSTEM teardown for an explicit brand: act under an unscoped (superadmin)
        // scope homed at the deployment's domain so the cross-domain reconcile can read +
        // drop THIS brand's rule. Sweep the rule(s) matching this service's role + url
        // pattern, so teardown does not need to have remembered the row id.
        var scope = net.hugmesh.commons.security.PrincipalDomain.superadminFor(deployment.domain());
        return routeAccess.list(scope)
                .filter(r -> deployment.domain() != null && deployment.domain().equals(r.domain())
                        && identity.casdoorRole().equals(r.role())
                        && identity.urlPattern().equals(r.urlPattern()))
                .flatMap(r -> routeAccess.remove(r.id(), scope))
                .then();
    }
}
