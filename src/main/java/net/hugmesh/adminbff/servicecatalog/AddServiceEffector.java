package net.hugmesh.adminbff.servicecatalog;

import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.reactive.TransactionalOperator;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import net.hugmesh.adminbff.argocd.ArgoCdClient;
import net.hugmesh.adminbff.routeaccess.RouteAccessService;
import net.hugmesh.adminbff.routeaccess.RouteRule;
import net.hugmesh.adminbff.servicecatalog.repourl.RepoUrlValidator;
import net.hugmesh.authcore.casdoor.CasdoorAdminClient;
import net.hugmesh.commons.security.PrincipalDomain;
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
 * delete role). Each leg is idempotent so a re-run / retry is safe: the route-access leg
 * REPLACES the rule set an earlier provision of the same deployment recorded (see below).
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
 * <h3>Which rules teardown removes: the ones provision recorded</h3>
 * Provision RECORDS every route-access row it writes against the deployment
 * ({@code service_deployment_route_rule}, {@link DeploymentRouteRuleRepository}), in the SAME
 * transaction as the rows themselves — a rule is never written without its record. Teardown
 * removes exactly the recorded rows, by id, and nothing else. It never matches on a rule's
 * pattern or role and it does not read the profile again, so, for every deployment that has
 * recorded rules (the one exception is the next section):
 * <ul>
 *   <li>a per-user or deny rule on the same pattern and role is never removed (it is in nobody's
 *       record);</li>
 *   <li>another deployment's rule is never removed, even when both deployments use the same
 *       profile and so wrote the same (pattern, role): each one owns its own row;</li>
 *   <li>a rule that already existed with exactly the shape of a grant is never removed;</li>
 *   <li>a profile EDITED or DELETED after provision changes nothing: the rules the provision
 *       actually wrote are the ones removed, and an expired lease never waits on a profile.</li>
 * </ul>
 * Provisioning the same deployment AGAIN replaces its recorded rule set — the new rows are
 * written and recorded and the earlier ones removed, in one transaction — so a retry does not
 * stack duplicates and a re-provision after a profile edit drops the grants the profile no longer
 * names.
 *
 * <h3>A deployment with NO recorded rules</h3>
 * A deployment that never recorded a rule was provisioned before rules were recorded, or was
 * never provisioned. For it, and only for it, teardown falls back to what the effector did
 * before records existed: it removes the ONE derived rule by shape. The shape is exactly what
 * that provision wrote (this brand, this brand's be-gateway, the derived pattern and role,
 * role-based, allow, mfa_required=false), and a row recorded for any deployment is skipped, so
 * here too a per-user or deny rule is left alone. Two limits remain on this path only:
 * <ul>
 *   <li>an unrecorded rule of exactly that shape that is not this deployment's (a hand-made
 *       one, or one written by ANOTHER unrecorded deployment of the same service in the same
 *       brand) cannot be told apart from the one the old provision wrote, and is removed with
 *       it (WARN-logged, as every removal on this path is);</li>
 *   <li>if such a deployment is provisioned AGAIN, it records its new rules and from then on
 *       teardown removes only those: the unrecorded rule its first provision wrote stays until
 *       someone deletes it.</li>
 * </ul>
 * A deployment that HAS recorded rules never takes this path, not even on a repeated teardown:
 * its records are stamped, never deleted.
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
    /** The record of which route-access rows each deployment's provision wrote. Teardown removes
     *  exactly the rows recorded here for its deployment. */
    private final DeploymentRouteRuleRepository ruleRecords;
    /** Wraps the route-access leg of a provision, so every rule and its record commit together
     *  or not at all. */
    private final TransactionalOperator tx;

    @org.springframework.beans.factory.annotation.Autowired
    public AddServiceEffector(ArgoCdClient argoCd,
                              @Nullable CasdoorAdminClient casdoor,
                              RouteAccessService routeAccess,
                              @Nullable KanikoBuildLauncher builder,
                              @Value("${app.appstore.repo-host-allowlist:}") String repoHostAllowlistCsv,
                              @Nullable AppProfileRepository profiles,
                              DeploymentRouteRuleRepository ruleRecords,
                              TransactionalOperator tx) {
        this.argoCd = argoCd;
        this.casdoor = casdoor;
        this.routeAccess = routeAccess;
        this.builder = builder;
        this.repoHostAllowlist = RepoUrlValidator.parseHostAllowlist(repoHostAllowlistCsv);
        this.profiles = profiles;
        this.ruleRecords = ruleRecords;
        this.tx = tx;
    }


    /** Convenience constructor with NO host allowlist (any well-formed, allowed-scheme,
     *  non-empty-host repo URL is accepted) — the structural scheme/host SSRF guards still run.
     *  Used by tests / wirings that do not configure {@code app.appstore.repo-host-allowlist}.
     *  It also wires NO app_profile store: a deployment WITHOUT a profileRef behaves exactly as
     *  before, one WITH a profileRef is refused (422) rather than provisioned without it. */
    public AddServiceEffector(ArgoCdClient argoCd,
                              @Nullable CasdoorAdminClient casdoor,
                              RouteAccessService routeAccess,
                              @Nullable KanikoBuildLauncher builder,
                              DeploymentRouteRuleRepository ruleRecords,
                              TransactionalOperator tx) {
        this(argoCd, casdoor, routeAccess, builder, "", null, ruleRecords, tx);
    }

    /** Test/wiring convenience: no host allowlist, with a profile store. */
    public AddServiceEffector(ArgoCdClient argoCd,
                              @Nullable CasdoorAdminClient casdoor,
                              RouteAccessService routeAccess,
                              @Nullable KanikoBuildLauncher builder,
                              @Nullable AppProfileRepository profiles,
                              DeploymentRouteRuleRepository ruleRecords,
                              TransactionalOperator tx) {
        this(argoCd, casdoor, routeAccess, builder, "", profiles, ruleRecords, tx);
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
     *       routes × roles product with one — and record each written rule against the
     *       deployment, replacing the rules an earlier provision of it recorded;</li>
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
        if (!hasId(deployment)) {
            // The rules a provision writes are recorded against the deployment's id; without
            // one they could never be removed again, so nothing is written at all.
            return Mono.error(ApiException.badRequest("deployment id is required: the"
                    + " route-access rules a provision writes are recorded against it"));
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
     * delete the ArgoCD Application, remove the route-access rules the deployment's provision
     * recorded, delete the Casdoor role. Each leg tolerates already-absent (idempotent). This is
     * the real effect the App-Store expiry loop emits via {@link EnforceActionEmitter} once the
     * effector is enabled. The app_profile store is NOT read: what is removed is what was
     * recorded, whatever the profile says now.
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

    // ── Profile resolution ───────────────────────────────────────────────

    private static boolean hasProfileRef(ServiceDeployment deployment) {
        return deployment.profileRef() != null && !deployment.profileRef().isBlank();
    }

    private static boolean hasId(ServiceDeployment deployment) {
        return deployment.id() != null && !deployment.id().isBlank();
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

    /**
     * The route-access leg of a provision, in ONE transaction: write every grant as its own rule
     * (its role may reach its URL pattern from the per-domain be-gateway, scoped to the
     * deployment's brand, with the profile's MFA requirement), record each written rule against
     * the deployment, then remove the rules an EARLIER provision of this same deployment
     * recorded. New rows first, old rows second, so the mirror the gateways poll never sees the
     * deployment without its grants; and all of it commits or none of it does, so a rule can
     * never exist without the record teardown needs to remove it.
     */
    private Mono<Void> addRouteRules(ServiceDeployment deployment, PerServiceIdentity identity,
                                     ResolvedAppProfile profile) {
        PrincipalDomain brand = PrincipalDomain.forDomain(deployment.domain());
        return ruleRecords.liveRuleIds(deployment.id()).collectList()
                .flatMap(earlier -> writeAndRecordRules(deployment, identity, profile)
                        .then(removeRecordedRules(earlier, brand)))
                .as(tx::transactional);
    }

    private Mono<Void> writeAndRecordRules(ServiceDeployment deployment, PerServiceIdentity identity,
                                           ResolvedAppProfile profile) {
        return Flux.fromIterable(grants(identity, profile))
                .concatMap(g -> routeAccess.add(ruleFor(deployment, identity, profile, g))
                        .flatMap(written -> ruleRecords.record(deployment.id(), written.id())))
                .then();
    }

    /** The rule one grant becomes: role-based, allow, on the per-domain be-gateway, scoped to
     *  the deployment's brand, carrying the profile's MFA requirement. */
    private static RouteRule ruleFor(ServiceDeployment deployment, PerServiceIdentity identity,
                                     ResolvedAppProfile profile, Grant g) {
        return new RouteRule(
                null,
                identity.domainSlugGateway(),
                g.urlPattern(),
                g.role(),
                null,
                true,
                deployment.domain(),
                profile.mfaRequired());
    }

    /** Remove the rules with these recorded ids, one after another, stamping each record once
     *  its rule is gone. The delete is SCOPED to the deployment's brand, so a recorded id can
     *  only ever remove a row of that brand; an id whose rule is already gone (an admin deleted
     *  it by hand) removes nothing and is stamped all the same. */
    private Mono<Void> removeRecordedRules(List<String> ruleIds, PrincipalDomain brand) {
        return Flux.fromIterable(ruleIds)
                .concatMap(id -> routeAccess.remove(id, brand).then(ruleRecords.markRemoved(id)))
                .then();
    }

    /** The route-access leg of a teardown: remove exactly the rules this deployment's provision
     *  recorded. Only a deployment with nothing recorded can reach the by-shape fallback. */
    private Mono<Void> removeRouteRules(ServiceDeployment deployment, PerServiceIdentity identity) {
        PrincipalDomain brand = PrincipalDomain.forDomain(deployment.domain());
        if (!hasId(deployment)) {
            return removeUnrecordedDerivedRule(deployment, identity, brand);
        }
        return ruleRecords.liveRuleIds(deployment.id()).collectList()
                .flatMap(recorded -> recorded.isEmpty()
                        ? removeDerivedRuleIfNeverRecorded(deployment, identity, brand)
                        : removeRecordedRules(recorded, brand));
    }

    /** Nothing live is recorded. If the deployment recorded rules before, they have been removed
     *  already and there is nothing to do; only one that NEVER recorded a rule falls back. */
    private Mono<Void> removeDerivedRuleIfNeverRecorded(ServiceDeployment deployment,
                                                        PerServiceIdentity identity,
                                                        PrincipalDomain brand) {
        return ruleRecords.hasEverRecorded(deployment.id())
                .flatMap(known -> known
                        ? Mono.<Void>empty()
                        : removeUnrecordedDerivedRule(deployment, identity, brand));
    }

    /**
     * The fallback for a deployment that never recorded a rule (provisioned before rules were
     * recorded, or never provisioned): remove its ONE derived rule by shape, as teardown did
     * before records existed. The match is exactly the row that provision wrote, and a row
     * recorded for any deployment is never taken, so a per-user rule, a deny rule, another
     * gateway's rule and any rule a deployment RECORDED all stay. An unrecorded rule of exactly
     * this shape cannot be told apart and goes too, whether it was made by hand or written by
     * another unrecorded deployment of the same service in the same brand, which is why every
     * removal here is a WARN.
     */
    private Mono<Void> removeUnrecordedDerivedRule(ServiceDeployment deployment,
                                                   PerServiceIdentity identity,
                                                   PrincipalDomain brand) {
        return routeAccess.list(brand)
                .filter(r -> isUnrecordedProvisionShape(r, identity))
                .collectList()
                .flatMapMany(Flux::fromIterable)
                .filterWhen(r -> ruleRecords.isRecorded(r.id()).map(recorded -> !recorded))
                .concatMap(r -> routeAccess.remove(r.id(), brand).then(Mono.just(r.id())))
                .collectList()
                .doOnNext(removed -> logUnrecordedRemoval(deployment, identity, removed))
                .then();
    }

    /** Exactly the one rule a provision wrote before rules were recorded: this brand's
     *  be-gateway, the derived pattern and role, role-based, allow, no MFA requirement. (The
     *  brand itself is already fixed by the scoped list this filters.) */
    private static boolean isUnrecordedProvisionShape(RouteRule r, PerServiceIdentity identity) {
        return identity.urlPattern().equals(r.urlPattern())
                && identity.casdoorRole().equals(r.role())
                && identity.domainSlugGateway().equals(r.gateway())
                && r.casdoorUser() == null
                && r.allow()
                && !r.mfaRequired();
    }

    private static void logUnrecordedRemoval(ServiceDeployment deployment, PerServiceIdentity identity,
                                             List<String> removed) {
        if (!removed.isEmpty()) {
            log.warn("[appstore-effector] teardown of {} in {}: deployment {} has no recorded"
                            + " route-access rules (provisioned before rules were recorded?) - removed"
                            + " {} BY SHAPE ({} -> {} on {}): {}",
                    deployment.serviceKey(), deployment.domain(), deployment.id(), removed.size(),
                    identity.casdoorRole(), identity.urlPattern(), identity.domainSlugGateway(), removed);
        }
    }
}
