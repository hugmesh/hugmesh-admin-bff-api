package net.hugmesh.adminbff.servicecatalog;

import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
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

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
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
 *
 * <h3>App-profile resolution (catalog-ui#3, first slice)</h3>
 * When the deployment carries a {@link ServiceDeployment#profileRef()}, the named
 * {@code app_profile} is loaded and parsed into a {@link ResolvedAppProfile} as the FIRST step of
 * provision — before any Casdoor, route-access, Kaniko or ArgoCD call — so an unknown ref, a
 * stored body the schema refuses, or a missing profile store fails the provision CLOSED (422)
 * with no effect at all. The parts this effector already owns are applied:
 * <ul>
 *   <li>{@code exposure.routes} — extra route-access url_patterns beside the derived
 *       {@code /api/<service>/};</li>
 *   <li>{@code roles[]} — extra {@code ROLE_<UPPER>} grants. The rule set is the full product
 *       ({derived pattern} ∪ routes) × ({derived role} ∪ roles), de-duplicated: the schema
 *       grants those roles "access to the service", so each one reaches every pattern the
 *       service exposes, the derived one included;</li>
 *   <li>{@code exposure.mfaRequired} — {@code mfa_required} on EVERY rule the provision writes,
 *       the derived one included (otherwise the derived pattern would be an MFA bypass).</li>
 * </ul>
 * {@code resources.*}, {@code certs.*} and {@code exposure.ports} are parsed but RECORDED ONLY:
 * no ArgoCD parameter channel or ExternalSecret parameter channel exists to hand them to yet, so
 * they are logged as not consumed. A deployment with NO profileRef never touches the profile
 * store and writes exactly the one derived rule (mfa_required=false) it always did.
 *
 * <p>Teardown re-resolves the profile and removes the same rule set. It does NOT fail closed: an
 * expired lease must still lose its Application, its derived rule and its role even if the
 * profile has since been deleted or broken — that case is logged as a WARN, because any
 * profile-derived rules then stay behind. Nothing records which rules a provision wrote, so a
 * profile EDITED between provision and teardown is torn down by its current contents, and a rule
 * that already existed in the brand with exactly the shape a profile grant writes (this gateway,
 * same pattern and role, role-based, allow) is indistinguishable from it and removed too. A
 * per-user or deny rule on the same pattern is never swept.
 */
@Service
@SuppressFBWarnings(value = "EI_EXPOSE_REP2",
        justification = "Spring constructor injection: the container owns this singleton collaborator and it is never mutated by this class after construction; a defensive copy of a bean is meaningless (not caller-owned mutable data).")
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
    /** The {@code app_profile} store a deployment's {@code profileRef} is resolved from. Null only
     *  in test wirings that predate profile resolution; a deployment that carries a profileRef is
     *  then REFUSED (fail closed) rather than provisioned without its profile. */
    @Nullable
    private final AppProfileRepository profiles;

    @org.springframework.beans.factory.annotation.Autowired
    public AddServiceEffector(ArgoCdClient argoCd,
                              @Nullable CasdoorAdminClient casdoor,
                              RouteAccessService routeAccess,
                              @Nullable KanikoBuildLauncher builder,
                              @Value("${app.appstore.repo-host-allowlist:}") String repoHostAllowlistCsv,
                              @Nullable AppProfileRepository profiles) {
        this.argoCd = argoCd;
        this.casdoor = casdoor;
        this.routeAccess = routeAccess;
        this.builder = builder;
        this.repoHostAllowlist = RepoUrlValidator.parseHostAllowlist(repoHostAllowlistCsv);
        this.profiles = profiles;
    }


    /** Convenience constructor with NO host allowlist (any well-formed, allowed-scheme,
     *  non-empty-host repo URL is accepted) — the structural scheme/host SSRF guards still run.
     *  Used by tests / wirings that do not configure {@code app.appstore.repo-host-allowlist}.
     *  It also wires NO app_profile store: a deployment WITHOUT a profileRef behaves exactly as
     *  before, one WITH a profileRef is refused (422) rather than provisioned without it. */
    public AddServiceEffector(ArgoCdClient argoCd,
                              @Nullable CasdoorAdminClient casdoor,
                              RouteAccessService routeAccess,
                              @Nullable KanikoBuildLauncher builder) {
        this(argoCd, casdoor, routeAccess, builder, "", null);
    }

    /** Test/wiring convenience: no host allowlist, with a profile store. */
    public AddServiceEffector(ArgoCdClient argoCd,
                              @Nullable CasdoorAdminClient casdoor,
                              RouteAccessService routeAccess,
                              @Nullable KanikoBuildLauncher builder,
                              @Nullable AppProfileRepository profiles) {
        this(argoCd, casdoor, routeAccess, builder, "", profiles);
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
     *   <li>add the per-service route-access rule(s) (role → the service's URL pattern(s))
     *       scoped to the deployment's brand — one rule without a profile, the profile's
     *       routes × roles product with one;</li>
     *   <li>create the ArgoCD Application that registers the descriptor repo (ships dark
     *       unless the effector is enabled).</li>
     * </ol>
     * A {@code profileRef} is resolved BEFORE step 1; an unknown or unresolvable one fails the
     * whole provision with a 422 and no effect.
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

        // Resolve the profile FIRST: every effect below is assembled inside the flatMap, so an
        // unknown / unresolvable profileRef fails before any Casdoor, route-access, Kaniko or
        // ArgoCD call is even made.
        return resolveForProvision(deployment)
                .doOnNext(profile -> logRecordedOnly(deployment, profile))
                .flatMap(profile -> provisionResolved(deployment, source, identity, appName, profile));
    }

    private Mono<String> provisionResolved(ServiceDeployment deployment, ServiceSource source,
                                           PerServiceIdentity identity, String appName,
                                           ResolvedAppProfile profile) {
        if (source.kind().requiresBuilder()) {
            // DOCKERFILE (or ZIP): builder is non-null here (checked above). Run the full
            // create sequence: role → route rule → Kaniko build → ArgoCD Application.
            // builder.build() returns the pushed image ref; .then() ignores the value because
            // ArgoCD points at the git repo, not the image ref directly.
            KanikoBuildLauncher b = java.util.Objects.requireNonNull(builder);
            return ensureRole(identity)
                    .then(addRouteRules(deployment, identity, profile))
                    .then(b.build(deployment.domain(), deployment.serviceKey(), source))
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
                .then(addRouteRules(deployment, identity, profile))
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
        return resolveForTeardown(deployment)
                .flatMap(profile -> argoCd.deleteApplication(appName)
                        .then(removeRouteRules(deployment, identity, profile))
                        .then(deleteRole(identity))
                        .doOnSuccess(v -> log.info(
                                "[appstore-effector] tore down {} in {} (app='{}', role='{}', enabled={})",
                                deployment.serviceKey(), deployment.domain(), appName, identity.casdoorRole(),
                                effectorEnabled())))
                .then();
    }

    // ── Profile resolution ───────────────────────────────────────────────

    private static boolean hasProfileRef(ServiceDeployment deployment) {
        return deployment.profileRef() != null && !deployment.profileRef().isBlank();
    }

    /** Provision-side resolution: NONE when there is no profileRef (the profile store is not
     *  touched); otherwise the parsed profile, or a 422 — never a silent fallback to NONE. */
    private Mono<ResolvedAppProfile> resolveForProvision(ServiceDeployment deployment) {
        if (!hasProfileRef(deployment)) {
            return Mono.just(ResolvedAppProfile.NONE);
        }
        String ref = deployment.profileRef();
        if (profiles == null) {
            return Mono.error(ApiException.unprocessable("service_deployment " + deployment.id()
                    + " references app_profile '" + ref + "' but no app_profile store is wired"
                    + " into the effector; refusing to provision without its profile"));
        }
        return profiles.findByName(ref)
                .switchIfEmpty(Mono.error(ApiException.unprocessable("service_deployment "
                        + deployment.id() + " references app_profile '" + ref
                        + "', which does not exist; create the profile or clear profileRef,"
                        + " then provision again")))
                .map(p -> ResolvedAppProfile.parse(p.name(), p.profileJson()));
    }

    /** Teardown-side resolution: like provision, but a missing / unresolvable profile degrades
     *  to NONE with a WARN instead of blocking the teardown of an expired lease. A store ERROR
     *  still propagates, so the expiry loop retries rather than half-tearing-down. */
    private Mono<ResolvedAppProfile> resolveForTeardown(ServiceDeployment deployment) {
        if (!hasProfileRef(deployment)) {
            return Mono.just(ResolvedAppProfile.NONE);
        }
        String ref = deployment.profileRef();
        if (profiles == null) {
            log.warn("[appstore-effector] teardown of {} in {}: no app_profile store wired to resolve"
                    + " profileRef '{}' - removing only the derived rule; profile-derived rules may"
                    + " remain", deployment.serviceKey(), deployment.domain(), ref);
            return Mono.just(ResolvedAppProfile.NONE);
        }
        return profiles.findByName(ref)
                .map(p -> {
                    try {
                        return ResolvedAppProfile.parse(p.name(), p.profileJson());
                    } catch (ApiException e) {
                        log.warn("[appstore-effector] teardown of {} in {}: {} - removing only the"
                                + " derived rule; profile-derived rules may remain",
                                deployment.serviceKey(), deployment.domain(), e.getMessage());
                        return ResolvedAppProfile.NONE;
                    }
                })
                .switchIfEmpty(Mono.fromSupplier(() -> {
                    log.warn("[appstore-effector] teardown of {} in {}: app_profile '{}' no longer"
                            + " exists - removing only the derived rule; profile-derived rules may"
                            + " remain", deployment.serviceKey(), deployment.domain(), ref);
                    return ResolvedAppProfile.NONE;
                }));
    }

    private static void logRecordedOnly(ServiceDeployment deployment, ResolvedAppProfile profile) {
        List<String> unconsumed = profile.recordedOnly();
        if (!unconsumed.isEmpty()) {
            log.info("[appstore-effector] app_profile '{}' for {} in {}: {} recorded only, NOT yet"
                    + " consumed (no ArgoCD / ExternalSecret parameter channel exists yet)",
                    profile.name(), deployment.serviceKey(), deployment.domain(), unconsumed);
        }
    }

    /** One (url_pattern, role) grant the provision writes. */
    record Grant(String urlPattern, String role) {
    }

    /** The de-duplicated, ordered rule set for this service under {@code profile}: the derived
     *  pattern first, then the profile's routes; for each, the derived role first, then the
     *  profile's roles. {@link ResolvedAppProfile#NONE} gives exactly the one derived grant. */
    static List<Grant> grants(PerServiceIdentity identity, ResolvedAppProfile profile) {
        Set<String> patterns = new LinkedHashSet<>();
        patterns.add(identity.urlPattern());
        patterns.addAll(profile.routes());
        Set<String> roles = new LinkedHashSet<>();
        roles.add(identity.casdoorRole());
        roles.addAll(profile.roles());
        List<Grant> out = new ArrayList<>();
        for (String p : patterns) {
            for (String r : roles) {
                out.add(new Grant(p, r));
            }
        }
        return out;
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

    /** The route-access rules: each grant's role may reach its URL pattern from the per-domain
     *  be-gateway, scoped to the deployment's brand, with the profile's MFA requirement. Written
     *  in order, one after another. */
    private Mono<Void> addRouteRules(ServiceDeployment deployment, PerServiceIdentity identity,
                                     ResolvedAppProfile profile) {
        return reactor.core.publisher.Flux.fromIterable(grants(identity, profile))
                .concatMap(g -> routeAccess.add(new RouteRule(
                        null,
                        identity.domainSlugGateway(),
                        g.urlPattern(),
                        g.role(),
                        null,
                        true,
                        deployment.domain(),
                        profile.mfaRequired())))
                .then();
    }

    private Mono<Void> removeRouteRules(ServiceDeployment deployment, PerServiceIdentity identity,
                                        ResolvedAppProfile profile) {
        // Internal SYSTEM teardown for an explicit brand: act under an unscoped (superadmin)
        // scope homed at the deployment's domain so the cross-domain reconcile can read +
        // drop THIS brand's rule. Sweep the rule(s) matching this service's role + url
        // pattern, so teardown does not need to have remembered the row id. The derived grant is
        // matched exactly as before (brand + role + pattern); a PROFILE-derived grant must also
        // match the shape provision writes (this gateway, role-based, allow) so a hand-made rule
        // for the same role + pattern - say a per-user deny - is not swept with it.
        var scope = net.hugmesh.commons.security.PrincipalDomain.superadminFor(deployment.domain());
        Set<Grant> grants = new LinkedHashSet<>(grants(identity, profile));
        Grant derived = new Grant(identity.urlPattern(), identity.casdoorRole());
        return routeAccess.list(scope)
                .filter(r -> deployment.domain() != null && deployment.domain().equals(r.domain()))
                .filter(r -> {
                    Grant g = new Grant(r.urlPattern(), r.role());
                    if (g.equals(derived)) {
                        return true;
                    }
                    return grants.contains(g)
                            && identity.domainSlugGateway().equals(r.gateway())
                            && r.casdoorUser() == null
                            && r.allow();
                })
                .concatMap(r -> routeAccess.remove(r.id(), scope).then())
                .then();
    }
}
