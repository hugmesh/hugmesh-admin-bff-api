package systems.hugmesh.adminbff.optionalservices;

import io.fabric8.kubernetes.api.model.ConfigMapBuilder;
import io.fabric8.kubernetes.client.KubernetesClient;
import io.fabric8.kubernetes.client.KubernetesClientException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * The REAL {@link InstalledServicesConfigMapWriter}: merge-patches the greying/capability
 * booleans of the {@code installed-services} ConfigMap ({@code hugmesh-policy} ns) —
 * the same second target {@code _opt_render_installed_services()} writes at BUILD time,
 * now maintained at RUNTIME. Clones the {@code Fabric8NodeStorageConfigMapWriter} idiom
 * (lazy {@link ClientFactory}, all exceptions swallowed to a boolean for next-tick retry).
 *
 * <p>Uses {@code edit(...)} (a computed JSON patch of ONLY the changed managed keys) so
 * services.json + workloadConsole + the reserved-prefixes ConfigMap stay ArgoCD-managed
 * and untouched — NOT a whole-object serverSideApply that would fight ArgoCD's field
 * manager. Persistence relies on the {@code apps/16} {@code ignoreDifferences} keystone.
 *
 * <p>{@link #computeDataPatch} is a package-visible TOTAL pure function (no cluster
 * touched) over the managed slug list — unit-tested offline.
 */
public class Fabric8InstalledServicesConfigMapWriter implements InstalledServicesConfigMapWriter {

    private static final Logger log =
            LoggerFactory.getLogger(Fabric8InstalledServicesConfigMapWriter.class);

    static final String CONFIGMAP_NAME = "installed-services";

    /** Supplies a configured client; separated so it can be stubbed in tests. */
    @FunctionalInterface
    public interface ClientFactory {
        KubernetesClient get();
    }

    private final ClientFactory clientFactory;
    private final String namespace;
    private final List<String> managedSlugs;

    public Fabric8InstalledServicesConfigMapWriter(ClientFactory clientFactory, String namespace,
                                                   List<String> managedSlugs) {
        this.clientFactory = clientFactory;
        this.namespace = (namespace == null || namespace.isBlank()) ? "hugmesh-policy" : namespace.trim();
        this.managedSlugs = List.copyOf(managedSlugs);
    }

    @Override
    public boolean mirror(Map<String, Boolean> desired) {
        Map<String, String> patch = computeDataPatch(desired);
        try (KubernetesClient client = clientFactory.get()) {
            var dsl = client.configMaps().inNamespace(namespace).withName(CONFIGMAP_NAME);
            if (dsl.get() == null) {
                log.warn("[optional-services-reconciler] ConfigMap {}/{} not found (retry next tick)",
                        namespace, CONFIGMAP_NAME);
                return false;
            }
            // edit() computes a JSON patch of only the changed managed keys — services.json
            // + workloadConsole (not in the patch) are left intact.
            dsl.edit(cm -> new ConfigMapBuilder(cm).addToData(patch).build());
            log.info("[optional-services-reconciler] mirrored {} installed-services boolean(s) into {}/{}",
                    patch.size(), namespace, CONFIGMAP_NAME);
            return true;
        } catch (KubernetesClientException e) {
            log.warn("[optional-services-reconciler] ConfigMap mirror failed (retry next tick): {}",
                    e.getMessage());
            return false;
        } catch (Exception e) {
            log.warn("[optional-services-reconciler] ConfigMap mirror errored (retry next tick): {}",
                    e.toString());
            return false;
        }
    }

    @Override
    public boolean isReal() {
        return true;
    }

    /**
     * TOTAL pure transform: the {@code data} keys to merge into the ConfigMap — EXACTLY the
     * managed slugs, each mapped to {@code "true"}/{@code "false"} from
     * {@code desired.getOrDefault(slug, false)}. Only managed slugs appear, so unmanaged
     * keys (services.json, workloadConsole) can never be written. Order = the managed list.
     */
    Map<String, String> computeDataPatch(Map<String, Boolean> desired) {
        Map<String, String> data = new LinkedHashMap<>();
        for (String slug : managedSlugs) {
            boolean on = desired != null && Boolean.TRUE.equals(desired.get(slug));
            data.put(slug, on ? "true" : "false");
        }
        return data;
    }
}
