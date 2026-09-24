package net.hugmesh.adminbff.backingservices;

import io.fabric8.kubernetes.api.model.ConfigMap;
import io.fabric8.kubernetes.api.model.ConfigMapBuilder;
import io.fabric8.kubernetes.api.model.apps.Deployment;
import io.fabric8.kubernetes.api.model.apps.DeploymentBuilder;
import io.fabric8.kubernetes.client.KubernetesClient;
import io.fabric8.kubernetes.client.KubernetesClientException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * The REAL {@link BackingServiceEffector}: converges the cluster to a recorded
 * {@link BackingServiceMode} by (1) merge-patching that service's two address keys into the
 * {@value BackingServiceEndpointPlan#CONFIGMAP_NAME} ConfigMap in THAT SERVICE'S OWN NAMESPACE,
 * then (2) stamping the ledger generation onto exactly that service's consumer Deployments so the
 * Deployment controller performs a targeted rolling restart.
 *
 * <h2>What the two operator decisions of 2026-09-17 mean for this class</h2>
 * <b>34a — one ConfigMap PER NAMESPACE.</b> The namespace comes from
 * {@link BackingServiceEndpointPlan.Plan#namespace()}, never from a field on this object. The
 * single-object alternative was recommended and DECLINED; this class is the fan-out writer whose
 * cost the operator accepted, and it is paired with one RBAC grant per namespace
 * ({@code specs/cluster/manifests/backing-service-endpoints/rbac.yaml}).
 *
 * <p><b>34b — a TARGETED ROLLING RESTART, and never call it anything else.</b> A
 * {@code configMapKeyRef} env var is read ONCE, when the kubelet creates the container. Patching
 * the ConfigMap alone would change nothing in any running pod while ArgoCD still reported every
 * Deployment Synced — the flip recorded, applied, reported green, and every pod still talking to
 * the old database. That is strictly worse than the {@link NoopBackingServiceEffector} it
 * replaces, whose logs at least say it did nothing. So step (2) is not an optimisation; it IS the
 * mechanism. Removing it does not make this effector faster, it makes it a lie.
 *
 * <h2>Two writers, one object</h2>
 * The generator's build-time {@code gate_backing_services()} writes the same ConfigMap's
 * {@code data} in the baked tree. This effector therefore performs a TARGETED MERGE-PATCH of only
 * the keys of the service being flipped ({@code edit(...)}, the
 * {@code Fabric8InstalledServicesConfigMapWriter} idiom) — never a whole-object replace, which
 * would clobber a concurrent flip and fight the build-time baseline of every other key. Its
 * persistence depends on the {@code ignoreDifferences} keystone in
 * {@code apps/17-backing-service-endpoints.yaml}; without both halves of that keystone ArgoCD's
 * selfHeal reverts this write within a sync interval.
 *
 * <h2>Idempotence, because the caller is a scheduled loop</h2>
 * {@link BackingServiceModeReconciler} is a {@code @Scheduled} tick over every recorded row. If
 * this class re-stamped the annotation each tick it would roll every flipped consumer every 30
 * seconds forever. So a converged service — keys already equal AND every consumer already
 * carrying this generation — is a no-op that patches nothing.
 *
 * <h2>What it deliberately does NOT do</h2>
 * <ul>
 *   <li><b>It does not claim the rollout finished.</b> It logs that a rolling update was
 *       requested and lets the next tick observe convergence. Reporting a completed rollout would
 *       need a bounded readiness wait, which nobody has exercised against this platform's
 *       {@code client-auth=need} mTLS and curl-based exec probes.</li>
 *   <li><b>It does not prune the in-mesh database workload.</b> That Application belongs to
 *       ArgoCD; deleting it at runtime is reverted by selfHeal within a sync interval, and it
 *       needs the optional-services list-element pattern instead. Re-pointing without pruning is
 *       correct and safe — the in-mesh database simply sits idle. Pruning without re-pointing is
 *       an outage.</li>
 *   <li><b>It moves no data.</b> A self-hosted → managed flip points a service at an EMPTY
 *       database; Liquibase then runs the entire changelog from changeSet 1 as the owner role.
 *       The ledger records intent; nothing dumps or restores.</li>
 * </ul>
 *
 * <p>Every failure is swallowed to a log line and retried on the next tick, the posture every
 * other effector on this platform uses — a reconcile loop that dies on a transient API error
 * stops converging everything else too.
 */
public class Fabric8BackingServiceEffector implements BackingServiceEffector {

    private static final Logger log = LoggerFactory.getLogger(Fabric8BackingServiceEffector.class);

    /** Supplies a configured client; separated so it can be stubbed in tests. */
    @FunctionalInterface
    public interface ClientFactory {
        KubernetesClient get();
    }

    private final ClientFactory clientFactory;

    public Fabric8BackingServiceEffector(ClientFactory clientFactory) {
        this.clientFactory = clientFactory;
    }

    @Override
    public Mono<Void> applyMode(BackingServiceMode desired) {
        return Mono.fromRunnable(() -> converge(desired))
                .subscribeOn(Schedulers.boundedElastic())
                .then();
    }

    @Override
    public boolean isReal() {
        return true;
    }

    /**
     * One convergence pass for one service. Package-visible so the mock-server test drives it
     * synchronously. Total: never throws.
     */
    void converge(BackingServiceMode desired) {
        var maybePlan = BackingServiceEndpointPlan.forMode(desired);
        if (maybePlan.isEmpty()) {
            log.warn("[backing-services-effector] REFUSED service={} mode={} — not actuatable by "
                            + "this effector (actuatable ids: {}). A recorded intent for an id "
                            + "with no ConfigMap key, a tier-3 docs-only service, an unknown "
                            + "mode, or a managed endpoint that is not a bare host:port is "
                            + "refused, never silently skipped.",
                    desired == null ? "-" : desired.serviceId(),
                    desired == null ? "-" : desired.mode(),
                    BackingServiceEndpointPlan.actuatableServiceIds());
            return;
        }
        converge(maybePlan.get());
    }

    /**
     * Apply one already-resolved plan. Package-visible so a test can drive the writer with a plan
     * in a namespace OTHER than {@code hugmesh-backend} — which is the only way to prove that the
     * decision-34a fan-out reads {@link BackingServiceEndpointPlan.Plan#namespace()} instead of a
     * constant, because every id that is actuatable TODAY happens to live in {@code
     * hugmesh-backend}. Total: never throws.
     */
    void converge(BackingServiceEndpointPlan.Plan plan) {
        try (KubernetesClient client = clientFactory.get()) {
            if (!patchEndpoints(client, plan)) {
                return;
            }
            rollConsumers(client, plan);
        } catch (KubernetesClientException e) {
            log.warn("[backing-services-effector] service={} failed (retry next tick): {}",
                    plan.serviceId(), e.getMessage());
        } catch (Exception e) {
            log.warn("[backing-services-effector] service={} errored (retry next tick): {}",
                    plan.serviceId(), e.toString());
        }
    }

    /**
     * Merge-patch EXACTLY this service's keys into its own namespace's ConfigMap. Returns false
     * only when the object is absent — the ConfigMap is git-owned, so a miss means the
     * {@code backing-service-endpoints} Application has not synced yet and the next tick retries.
     * An absent object is never created here: creating it would put an object outside ArgoCD's
     * ownership and hide the real fault.
     */
    private boolean patchEndpoints(KubernetesClient client, BackingServiceEndpointPlan.Plan plan) {
        var dsl = client.configMaps().inNamespace(plan.namespace()).withName(plan.configMapName());
        ConfigMap current = dsl.get();
        if (current == null) {
            log.warn("[backing-services-effector] ConfigMap {}/{} not found — service={} not "
                            + "converged (retry next tick). This object is git-owned; it is not "
                            + "created here.",
                    plan.namespace(), plan.configMapName(), plan.serviceId());
            return false;
        }
        Map<String, String> data = current.getData();
        boolean already = data != null && plan.data().entrySet().stream()
                .allMatch(en -> en.getValue().equals(data.get(en.getKey())));
        if (already) {
            log.debug("[backing-services-effector] {}/{} already carries service={} keys — no patch",
                    plan.namespace(), plan.configMapName(), plan.serviceId());
            return true;
        }
        dsl.edit(cm -> new ConfigMapBuilder(cm).addToData(plan.data()).build());
        log.info("[backing-services-effector] merge-patched {} key(s) for service={} into {}/{} "
                        + "(generation={})",
                plan.data().size(), plan.serviceId(), plan.namespace(), plan.configMapName(),
                plan.generation());
        return true;
    }

    /**
     * DECISION 34b: stamp {@value BackingServiceEndpointPlan#GENERATION_ANNOTATION} onto the pod
     * TEMPLATE of exactly this service's consumer Deployments, so the Deployment controller does a
     * normal rolling update and the new pods read the new ConfigMap value. A consumer already
     * carrying this generation is skipped, so a scheduled re-tick rolls nothing.
     *
     * <p>The annotation goes on {@code spec.template.metadata.annotations} — NOT on the
     * Deployment's own metadata, which no pod ever reads and which would trigger no rollout at all.
     */
    private void rollConsumers(KubernetesClient client, BackingServiceEndpointPlan.Plan plan) {
        List<String> rolled = new ArrayList<>();
        List<String> missing = new ArrayList<>();
        for (String name : plan.consumerDeployments()) {
            var dsl = client.apps().deployments().inNamespace(plan.namespace()).withName(name);
            Deployment current = dsl.get();
            if (current == null) {
                missing.add(name);
                continue;
            }
            String have = current.getSpec() == null || current.getSpec().getTemplate() == null
                    || current.getSpec().getTemplate().getMetadata() == null
                    || current.getSpec().getTemplate().getMetadata().getAnnotations() == null
                    ? null
                    : current.getSpec().getTemplate().getMetadata().getAnnotations()
                            .get(BackingServiceEndpointPlan.GENERATION_ANNOTATION);
            if (plan.generationAnnotationValue().equals(have)) {
                continue;
            }
            dsl.edit(d -> new DeploymentBuilder(d)
                    .editSpec()
                    .editTemplate()
                    .editOrNewMetadata()
                    .addToAnnotations(BackingServiceEndpointPlan.GENERATION_ANNOTATION,
                            plan.generationAnnotationValue())
                    .endMetadata()
                    .endTemplate()
                    .endSpec()
                    .build());
            rolled.add(name);
        }
        if (!missing.isEmpty()) {
            log.warn("[backing-services-effector] service={} consumer Deployment(s) {} absent in "
                            + "{} — those pods keep the OLD address until they exist and are "
                            + "rolled (retry next tick)",
                    plan.serviceId(), missing, plan.namespace());
        }
        if (rolled.isEmpty()) {
            log.debug("[backing-services-effector] service={} consumers already at generation {} "
                    + "— nothing rolled", plan.serviceId(), plan.generation());
            return;
        }
        // Deliberately NOT "rollout complete": this reports what was REQUESTED. The Deployment
        // controller owns the rollout; the next reconcile tick observes convergence.
        log.info("[backing-services-effector] requested a TARGETED ROLLING RESTART of {} "
                        + "Deployment(s) {} in {} for service={} (generation={}). This is a "
                        + "restart, not a live re-dial: configMapKeyRef env is resolved once at "
                        + "container creation.",
                rolled.size(), rolled, plan.namespace(), plan.serviceId(), plan.generation());
    }
}
