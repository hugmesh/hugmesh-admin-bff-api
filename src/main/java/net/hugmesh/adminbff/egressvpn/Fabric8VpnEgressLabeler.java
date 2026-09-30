package net.hugmesh.adminbff.egressvpn;

import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import io.fabric8.kubernetes.api.model.HasMetadata;
import io.fabric8.kubernetes.api.model.LabelSelector;
import io.fabric8.kubernetes.api.model.Pod;
import io.fabric8.kubernetes.api.model.PodBuilder;
import io.fabric8.kubernetes.api.model.apps.Deployment;
import io.fabric8.kubernetes.api.model.apps.DeploymentBuilder;
import io.fabric8.kubernetes.api.model.apps.StatefulSet;
import io.fabric8.kubernetes.api.model.apps.StatefulSetBuilder;
import io.fabric8.kubernetes.client.KubernetesClient;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

/**
 * The REAL {@link VpnEgressLabeler}: converges the {@code hugmesh.net/vpn-egress}
 * label over the Deployments/StatefulSets + their live pods in the egress namespace from the
 * ACTIVE {@code vpn_node_assignment} set.
 *
 * <h3>Slug → workload resolution (deterministic, covers the shipped manifests)</h3>
 * A workload is "named by" a slug when its {@code metadata.name} equals the slug (akkoma,
 * tuwunel) OR equals {@code hugmesh-<slug>} (hugmesh-coturn) OR its
 * {@code app.kubernetes.io/name} label equals the slug. Pods are resolved via the matched
 * workload's {@code spec.selector.matchLabels} (the shipped manifests use matchLabels only;
 * matchExpressions are not consulted).
 *
 * <h3>Restart-free + fail-closed</h3>
 * The workload marker lands on {@code metadata.labels} — deliberately NOT
 * {@code spec.template.metadata.labels}, which would rolling-restart the service on every
 * assignment flip. Live pods are labelled directly (the NetworkPolicy selects PODS); a pod
 * created between sweeps starts UNLABELLED (default-deny direct egress — fail-closed onto the
 * Squid-proxy path, never a WAN leak) until the next tick re-labels it. Un-labeling REMOVES
 * the key. A stray labelled pod matching no desired workload is swept clean too.
 *
 * <p>Clones the {@code Fabric8InstanceConfigMapWriter} client discipline: lazy
 * {@code ClientFactory}, {@code Mono.usingWhen} acquire/sweep/ALWAYS-close on
 * {@code boundedElastic}, and every failure swallowed to a 0 count (retry next tick / next
 * mutation — the admin mutation that triggered a fast-path reconcile never fails on it).
 */
@SuppressFBWarnings(value = "EI_EXPOSE_REP2",
        justification = "Spring constructor injection: the container owns this singleton collaborator and it is never mutated by this class after construction; a defensive copy of a bean is meaningless (not caller-owned mutable data).")
public class Fabric8VpnEgressLabeler implements VpnEgressLabeler {

    private static final Logger log = LoggerFactory.getLogger(Fabric8VpnEgressLabeler.class);

    /** Supplies a configured client; separated so it can be stubbed in tests. */
    @FunctionalInterface
    public interface ClientFactory {
        KubernetesClient get();
    }

    private final ClientFactory clientFactory;
    private final VpnNodeAssignmentRepository assignments;
    private final String namespace;
    private final List<String> domainWideSlugs;

    public Fabric8VpnEgressLabeler(ClientFactory clientFactory,
                                   VpnNodeAssignmentRepository assignments,
                                   String namespace, List<String> domainWideSlugs) {
        this.clientFactory = clientFactory;
        this.assignments = assignments;
        this.namespace = (namespace == null || namespace.isBlank()) ? "hugmesh-backend" : namespace;
        this.domainWideSlugs = List.copyOf(domainWideSlugs);
    }

    @Override
    public Mono<Long> reconcile() {
        return assignments.listActiveAll().collectList()
                .flatMap(active -> {
                    Set<String> slugs = desiredSlugs(active, domainWideSlugs);
                    return Mono.usingWhen(
                                    Mono.fromCallable(clientFactory::get),
                                    client -> Mono.fromCallable(() -> sweep(client, slugs)),
                                    client -> Mono.fromRunnable(client::close))
                            .subscribeOn(Schedulers.boundedElastic());
                })
                .doOnNext(n -> {
                    if (n > 0) {
                        log.info("[egress-vpn-labeler] converged {} — {} object(s) changed",
                                LABEL_KEY, n);
                    }
                })
                .onErrorResume(Exception.class, e -> {
                    log.warn("[egress-vpn-labeler] sweep failed (retry next tick/mutation): {}",
                            e.toString());
                    return Mono.just(0L);
                });
    }

    @Override
    public boolean isReal() {
        return true;
    }

    /**
     * The service-slug set the ACTIVE assignments name (pure — unit-tested in isolation): a
     * slug-carrying assignment contributes its slug; an all-services (null/blank-slug)
     * assignment contributes the whole configured public set.
     */
    static Set<String> desiredSlugs(List<VpnNodeAssignment> active, List<String> domainWideSlugs) {
        Set<String> out = new TreeSet<>();
        for (VpnNodeAssignment a : active) {
            if (!a.isActive()) continue;
            if (a.serviceSlug() == null || a.serviceSlug().isBlank()) {
                out.addAll(domainWideSlugs);
            } else {
                out.add(a.serviceSlug());
            }
        }
        return out;
    }

    /** Whether one workload is named by any desired slug (the resolution rule above). */
    static boolean wantsLabel(HasMetadata workload, Set<String> slugs) {
        String name = workload.getMetadata().getName();
        Map<String, String> labels = workload.getMetadata().getLabels();
        for (String slug : slugs) {
            if (slug.equals(name) || ("hugmesh-" + slug).equals(name)) return true;
            if (labels != null && slug.equals(labels.get("app.kubernetes.io/name"))) return true;
        }
        return false;
    }

    /** One synchronous convergence pass (blocking fabric8 I/O — runs on boundedElastic). */
    private long sweep(KubernetesClient client, Set<String> slugs) {
        long changed = 0;
        Set<String> desiredPods = new HashSet<>();
        for (Deployment d : client.apps().deployments().inNamespace(namespace).list().getItems()) {
            boolean want = wantsLabel(d, slugs);
            changed += reconcileDeploymentMeta(client, d, want);
            changed += reconcilePods(client, want, d.getSpec() == null ? null : d.getSpec().getSelector(),
                    desiredPods);
        }
        for (StatefulSet s : client.apps().statefulSets().inNamespace(namespace).list().getItems()) {
            boolean want = wantsLabel(s, slugs);
            changed += reconcileStatefulSetMeta(client, s, want);
            changed += reconcilePods(client, want, s.getSpec() == null ? null : s.getSpec().getSelector(),
                    desiredPods);
        }
        // Drift: a still-labelled pod no longer backed by any desired workload (workload
        // deleted / selector changed) is swept clean.
        for (Pod p : client.pods().inNamespace(namespace).withLabel(LABEL_KEY, LABEL_VALUE)
                .list().getItems()) {
            if (!desiredPods.contains(p.getMetadata().getName())) {
                editPodLabel(client, p.getMetadata().getName(), false);
                changed++;
            }
        }
        return changed;
    }

    private long reconcileDeploymentMeta(KubernetesClient client, Deployment d, boolean want) {
        if (want == hasLabel(d)) return 0;
        client.apps().deployments().inNamespace(namespace).withName(d.getMetadata().getName())
                .edit(cur -> {
                    DeploymentBuilder b = new DeploymentBuilder(cur);
                    if (want) b.editMetadata().addToLabels(LABEL_KEY, LABEL_VALUE).endMetadata();
                    else b.editMetadata().removeFromLabels(LABEL_KEY).endMetadata();
                    return b.build();
                });
        log.info("[egress-vpn-labeler] {} Deployment {}/{}", want ? "labelled" : "un-labelled",
                namespace, d.getMetadata().getName());
        return 1;
    }

    private long reconcileStatefulSetMeta(KubernetesClient client, StatefulSet s, boolean want) {
        if (want == hasLabel(s)) return 0;
        client.apps().statefulSets().inNamespace(namespace).withName(s.getMetadata().getName())
                .edit(cur -> {
                    StatefulSetBuilder b = new StatefulSetBuilder(cur);
                    if (want) b.editMetadata().addToLabels(LABEL_KEY, LABEL_VALUE).endMetadata();
                    else b.editMetadata().removeFromLabels(LABEL_KEY).endMetadata();
                    return b.build();
                });
        log.info("[egress-vpn-labeler] {} StatefulSet {}/{}", want ? "labelled" : "un-labelled",
                namespace, s.getMetadata().getName());
        return 1;
    }

    /** Converge the live pods behind one workload's matchLabels selector. */
    private long reconcilePods(KubernetesClient client, boolean want, LabelSelector selector,
                               Set<String> desiredPods) {
        Map<String, String> sel = selector == null ? null : selector.getMatchLabels();
        if (sel == null || sel.isEmpty()) return 0;
        long changed = 0;
        for (Pod p : client.pods().inNamespace(namespace).withLabels(sel).list().getItems()) {
            String podName = p.getMetadata().getName();
            if (want) desiredPods.add(podName);
            if (want == hasLabel(p)) continue;
            editPodLabel(client, podName, want);
            changed++;
        }
        return changed;
    }

    private void editPodLabel(KubernetesClient client, String podName, boolean want) {
        client.pods().inNamespace(namespace).withName(podName).edit(cur -> {
            PodBuilder b = new PodBuilder(cur);
            if (want) b.editMetadata().addToLabels(LABEL_KEY, LABEL_VALUE).endMetadata();
            else b.editMetadata().removeFromLabels(LABEL_KEY).endMetadata();
            return b.build();
        });
        log.info("[egress-vpn-labeler] {} Pod {}/{}", want ? "labelled" : "un-labelled",
                namespace, podName);
    }

    private static boolean hasLabel(HasMetadata obj) {
        Map<String, String> labels = obj.getMetadata().getLabels();
        return labels != null && LABEL_VALUE.equals(labels.get(LABEL_KEY));
    }
}
