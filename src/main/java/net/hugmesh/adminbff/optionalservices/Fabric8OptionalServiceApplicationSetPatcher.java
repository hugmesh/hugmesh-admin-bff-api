package net.hugmesh.adminbff.optionalservices;

import io.fabric8.kubernetes.api.model.GenericKubernetesResource;
import io.fabric8.kubernetes.client.KubernetesClient;
import io.fabric8.kubernetes.client.KubernetesClientException;
import io.fabric8.kubernetes.client.dsl.base.ResourceDefinitionContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * The REAL {@link OptionalServiceApplicationSetPatcher}: a targeted read-modify-write of
 * the {@code optional-services} ApplicationSet's inline list-generator element
 * {@code installed} flags ({@code apps/13a-optional-services.yaml},
 * {@code /spec/generators/0/list/elements}). Uses the fabric8 generic-resource API (the
 * ArgoCD types are not fabric8-shipped models — the SAME approach {@code cloudbackup.
 * VeleroBackupEffector} / {@code Fabric8VeleroStatusReader} use for velero.io CRs).
 *
 * <p>Read-modify-write (NOT a whole-object serverSideApply, which would fight ArgoCD's
 * field manager): {@code get()} the live ApplicationSet, flip only the {@code installed}
 * values on the matching elements, then {@code update()} (PUT with the fetched
 * resourceVersion — optimistic concurrency). Single-writer under the Lease, so there is
 * no second writer to race. The {@link ClientFactory} builds the client LAZILY (per
 * apply) so a transient API-server blip never bricks BFF boot; ALL exceptions are
 * swallowed to a {@code false} return so a failed apply is retried next tick.
 *
 * <p>The transform {@link #applyDesiredToElements} is a package-visible TOTAL pure
 * function (no cluster touched) — the offline keystone test asserts the exact flip on a
 * fixture that mirrors 13a.
 */
public class Fabric8OptionalServiceApplicationSetPatcher implements OptionalServiceApplicationSetPatcher {

    private static final Logger log =
            LoggerFactory.getLogger(Fabric8OptionalServiceApplicationSetPatcher.class);

    /** The optional-services ApplicationSet (argoproj.io/v1alpha1, namespaced). */
    static final String APPSET_NAME = "optional-services";

    static final ResourceDefinitionContext APPSET_RDC = new ResourceDefinitionContext.Builder()
            .withGroup("argoproj.io").withVersion("v1alpha1").withKind("ApplicationSet")
            .withPlural("applicationsets").withNamespaced(true).build();

    /** Supplies a configured client; separated so it can be stubbed in tests. */
    @FunctionalInterface
    public interface ClientFactory {
        KubernetesClient get();
    }

    private final ClientFactory clientFactory;
    private final String namespace;

    public Fabric8OptionalServiceApplicationSetPatcher(ClientFactory clientFactory, String namespace) {
        this.clientFactory = clientFactory;
        this.namespace = (namespace == null || namespace.isBlank()) ? "devops" : namespace.trim();
    }

    @Override
    public boolean apply(Map<String, Boolean> desired) {
        try (KubernetesClient client = clientFactory.get()) {
            GenericKubernetesResource live = client.genericKubernetesResources(APPSET_RDC)
                    .inNamespace(namespace).withName(APPSET_NAME).get();
            if (live == null) {
                log.warn("[optional-services-reconciler] ApplicationSet {}/{} not found (retry next tick)",
                        namespace, APPSET_NAME);
                return false;
            }
            List<Map<String, Object>> current = extractElements(live);
            if (current == null) {
                log.warn("[optional-services-reconciler] ApplicationSet {}/{} has no list-generator elements "
                        + "at /spec/generators/0/list/elements (retry next tick)", namespace, APPSET_NAME);
                return false;
            }
            List<Map<String, Object>> next = applyDesiredToElements(current, desired);
            if (next.equals(current)) {
                log.debug("[optional-services-reconciler] ApplicationSet elements already converged — no write");
                return true;
            }
            setElements(live, next);
            client.genericKubernetesResources(APPSET_RDC).inNamespace(namespace).resource(live).update();
            log.info("[optional-services-reconciler] patched ApplicationSet {}/{} element installed flags "
                    + "({} desired slug(s))", namespace, APPSET_NAME, desired == null ? 0 : desired.size());
            return true;
        } catch (KubernetesClientException e) {
            log.warn("[optional-services-reconciler] ApplicationSet patch failed (retry next tick): {}",
                    e.getMessage());
            return false;
        } catch (Exception e) {
            log.warn("[optional-services-reconciler] ApplicationSet patch errored (retry next tick): {}",
                    e.toString());
            return false;
        }
    }

    @Override
    public boolean isReal() {
        return true;
    }

    /**
     * TOTAL pure transform: return a NEW element list where, for each element whose
     * {@code slug} is a key of {@code desired}, {@code installed} is set to the string
     * {@code "true"}/{@code "false"}; every other field and every element whose slug is
     * absent from {@code desired} is preserved verbatim. Order is preserved. Never
     * mutates the input. A null/empty {@code desired} returns a faithful copy (no flips).
     */
    static List<Map<String, Object>> applyDesiredToElements(List<Map<String, Object>> elements,
                                                            Map<String, Boolean> desired) {
        List<Map<String, Object>> out = new ArrayList<>();
        if (elements == null) {
            return out;
        }
        for (Map<String, Object> el : elements) {
            Map<String, Object> copy = new LinkedHashMap<>(el);
            Object slug = copy.get("slug");
            if (slug != null && desired != null && desired.containsKey(slug.toString())) {
                copy.put("installed", Boolean.TRUE.equals(desired.get(slug.toString())) ? "true" : "false");
            }
            out.add(copy);
        }
        return out;
    }

    // ── generic-resource navigation (spec/generators[0]/list/elements as untyped maps) ──

    @SuppressWarnings("unchecked")
    private static List<Map<String, Object>> extractElements(GenericKubernetesResource r) {
        Map<String, Object> list = listGenerator(r);
        if (list == null) {
            return null;
        }
        Object elements = list.get("elements");
        if (elements instanceof List<?> l) {
            List<Map<String, Object>> out = new ArrayList<>();
            for (Object o : l) {
                if (o instanceof Map<?, ?> m) {
                    out.add((Map<String, Object>) m);
                }
            }
            return out;
        }
        return null;
    }

    private static void setElements(GenericKubernetesResource r, List<Map<String, Object>> next) {
        Map<String, Object> list = listGenerator(r);
        if (list != null) {
            list.put("elements", next);
        }
    }

    /** Navigate to spec.generators[0].list (the map that carries {@code elements}), or null. */
    @SuppressWarnings("unchecked")
    private static Map<String, Object> listGenerator(GenericKubernetesResource r) {
        Object spec = r.getAdditionalProperties() == null ? null : r.getAdditionalProperties().get("spec");
        if (!(spec instanceof Map<?, ?> specMap)) {
            return null;
        }
        Object generators = ((Map<String, Object>) specMap).get("generators");
        if (!(generators instanceof List<?> genList) || genList.isEmpty()) {
            return null;
        }
        Object first = genList.get(0);
        if (!(first instanceof Map<?, ?> firstMap)) {
            return null;
        }
        Object list = ((Map<String, Object>) firstMap).get("list");
        return (list instanceof Map<?, ?> listMap) ? (Map<String, Object>) listMap : null;
    }
}
