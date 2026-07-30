package systems.hugmesh.adminbff.optionalservices;

import io.fabric8.kubernetes.api.model.GenericKubernetesResource;
import io.fabric8.kubernetes.api.model.GenericKubernetesResourceList;
import io.fabric8.kubernetes.client.KubernetesClient;
import io.fabric8.kubernetes.client.dsl.base.ResourceDefinitionContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * The REAL {@link OptionalServiceClient}: lists the {@code OptionalService}
 * ({@code platform.hugmesh.systems/v1alpha1}) CRs and writes their {@code /status}
 * subresource via the fabric8 generic-resource API — the SAME idiom
 * {@code cloudbackup.Fabric8VeleroStatusReader} uses (the platform ships no typed
 * {@code CustomResource} model). The {@link ClientFactory} builds the client LAZILY (per
 * call) so a transient API-server blip never bricks BFF boot; failures are swallowed
 * (status write) / surfaced as an empty list (read) so the reconcile tick never dies.
 */
public class Fabric8OptionalServiceClient implements OptionalServiceClient {

    private static final Logger log = LoggerFactory.getLogger(Fabric8OptionalServiceClient.class);

    static final ResourceDefinitionContext OPTSVC_RDC = new ResourceDefinitionContext.Builder()
            .withGroup("platform.hugmesh.systems").withVersion("v1alpha1")
            .withKind("OptionalService").withPlural("optionalservices").withNamespaced(true).build();

    /** Supplies a configured client; separated so it can be stubbed in tests. */
    @FunctionalInterface
    public interface ClientFactory {
        KubernetesClient get();
    }

    private final ClientFactory clientFactory;
    private final String namespace;

    public Fabric8OptionalServiceClient(ClientFactory clientFactory, String namespace) {
        this.clientFactory = clientFactory;
        this.namespace = (namespace == null || namespace.isBlank()) ? "devops" : namespace.trim();
    }

    @Override
    public List<OptionalServiceCr> listDesired() {
        try (KubernetesClient client = clientFactory.get()) {
            GenericKubernetesResourceList list = client.genericKubernetesResources(OPTSVC_RDC)
                    .inNamespace(namespace).list();
            List<OptionalServiceCr> out = new ArrayList<>();
            if (list != null && list.getItems() != null) {
                for (GenericKubernetesResource cr : list.getItems()) {
                    OptionalServiceCr p = project(cr);
                    if (p != null) {
                        out.add(p);
                    }
                }
            }
            return out;
        } catch (Exception e) {
            log.warn("[optional-services-reconciler] listing OptionalService CRs failed (empty this tick): {}",
                    e.toString());
            return List.of();
        }
    }

    @Override
    public boolean updateStatus(OptionalServiceCr cr, OptionalServiceStatus status) {
        if (cr == null || status == null) {
            return false;
        }
        try (KubernetesClient client = clientFactory.get()) {
            GenericKubernetesResource live = client.genericKubernetesResources(OPTSVC_RDC)
                    .inNamespace(namespace).withName(cr.name()).get();
            if (live == null) {
                log.warn("[optional-services-reconciler] OptionalService {}/{} vanished before status write",
                        namespace, cr.name());
                return false;
            }
            live.setAdditionalProperty("status", statusMap(status));
            client.genericKubernetesResources(OPTSVC_RDC).inNamespace(namespace).resource(live).updateStatus();
            return true;
        } catch (Exception e) {
            log.warn("[optional-services-reconciler] status write for {} failed (retry next tick): {}",
                    cr.name(), e.toString());
            return false;
        }
    }

    @Override
    public boolean isReal() {
        return true;
    }

    /** Project one generic CR to the fabric8-free {@link OptionalServiceCr}. Null if it has no slug. */
    @SuppressWarnings("unchecked")
    private static OptionalServiceCr project(GenericKubernetesResource cr) {
        Object spec = cr.getAdditionalProperties() == null ? null : cr.getAdditionalProperties().get("spec");
        if (!(spec instanceof Map<?, ?> specMap)) {
            return null;
        }
        Map<String, Object> s = (Map<String, Object>) specMap;
        Object slug = s.get("slug");
        if (slug == null) {
            return null;
        }
        var meta = cr.getMetadata();
        long generation = meta != null && meta.getGeneration() != null ? meta.getGeneration() : 0L;
        String rv = meta != null ? meta.getResourceVersion() : null;
        String name = meta != null ? meta.getName() : slug.toString();
        String ns = meta != null ? meta.getNamespace() : null;
        return new OptionalServiceCr(
                name, ns, slug.toString(), truthy(s.get("enabled")),
                str(s.get("reason")), str(s.get("requestedBy")), generation, rv);
    }

    private Map<String, Object> statusMap(OptionalServiceStatus st) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("observedGeneration", st.observedGeneration());
        m.put("installed", st.installed());
        m.put("phase", st.phase());
        if (st.applicationName() != null) {
            m.put("applicationName", st.applicationName());
        }
        if (st.lastReconcileTime() != null) {
            m.put("lastReconcileTime", st.lastReconcileTime().toString());
        }
        List<Map<String, Object>> conds = new ArrayList<>();
        if (st.conditions() != null) {
            for (OptionalServiceStatus.Condition c : st.conditions()) {
                Map<String, Object> cm = new LinkedHashMap<>();
                cm.put("type", c.type());
                cm.put("status", c.status());
                cm.put("reason", c.reason());
                cm.put("message", c.message());
                cm.put("observedGeneration", c.observedGeneration());
                cm.put("lastTransitionTime",
                        c.lastTransitionTime() == null ? null : c.lastTransitionTime().toString());
                conds.add(cm);
            }
        }
        m.put("conditions", conds);
        return m;
    }

    private static boolean truthy(Object v) {
        return Boolean.TRUE.equals(v) || "true".equalsIgnoreCase(String.valueOf(v));
    }

    private static String str(Object v) {
        return v == null ? null : v.toString();
    }
}
