package net.hugmesh.adminbff.cloudbackup;

import io.fabric8.kubernetes.client.KubernetesClientBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

/**
 * Wires the REAL Velero {@link BackupEffector} + the real {@link RunningServiceProvider} the
 * cloud-backups foundation hands off to — gated behind ONE flag,
 * {@code app.backups.effector.enabled} (DEFAULT false). The naming mirrors the App-Store
 * {@code app.appstore.effector.enabled} effector gate and the workload-console
 * {@code app.workload-console.k8s.enabled} k8s seam.
 *
 * <h3>SHIPS DARK (Noop/Stub stay the default)</h3>
 * With the flag OFF (the DEFAULT — every dev/test/CI run and every deployment until the
 * generator provisions Velero + the BackupStorageLocation/credentials) NEITHER bean here is
 * created, so the foundation's component-scanned defaults win:
 * <ul>
 *   <li>{@code @Component @ConditionalOnMissingBean NoopBackupEffector} — the dark effector
 *       (no Velero CR is emitted; a created set stays {@code pending});</li>
 *   <li>{@code @Component @ConditionalOnMissingBean StubRunningServiceProvider} — the documented
 *       installed-services menu (no cluster read).</li>
 * </ul>
 * The {@link BackupEffectorWiringTest} pins this: with no property only the Noop/Stub beans are
 * present (single-bean, {@code instanceof Noop/Stub}); flipping the flag swaps in the Velero
 * effector + ConfigMap provider (still single-bean). The {@code @ConditionalOnMissingBean}
 * guard on these beans keeps the foundation defaults the safety net even if the real bean fails
 * to construct.
 *
 * <h3>Lazy client (boot never depends on a cluster)</h3>
 * The fabric8 {@code KubernetesClient} is built LAZILY per apply/read (via the supplier), so a
 * missing in-cluster context can never fail BFF boot — only an actual backup/restore/menu-read
 * touches the API server. The in-cluster deployment flips the flag true with the least-privilege
 * Velero ServiceAccount token mounted.
 *
 * <h3>Follow-on (NOT this leg)</h3>
 * This leg references the Velero {@code BackupStorageLocation} by name and reads the
 * generator-written installed-services ConfigMap; it does NOT install Velero, provision the BSL,
 * or wire ESO/Vault credentials — that is the generator leg. See the PR body's follow-on list.
 */
@Configuration(proxyBeanMethods = false)
public class BackupEffectorConfig {

    private static final Logger log = LoggerFactory.getLogger(BackupEffectorConfig.class);

    /** The Velero CR factory (pure). Built whenever the effector is enabled so both the real
     *  effector AND the ConfigMap provider can share it / the namespace config. */
    @Bean
    @ConditionalOnProperty(name = "app.backups.effector.enabled", havingValue = "true")
    VeleroResourceFactory veleroResourceFactory(
            @Value("${app.backups.effector.velero-namespace:velero}") String veleroNamespace,
            @Value("${app.backups.effector.brand-namespace-suffixes:be,fe}") String suffixes,
            @Value("${app.backups.effector.backup-ttl:720h0m0s}") String backupTtl) {
        List<String> suffixList = Arrays.stream(suffixes == null ? new String[0] : suffixes.split(","))
                .map(String::trim).filter(s -> !s.isBlank()).collect(Collectors.toList());
        log.info("[cloud-backup] Velero effector ENABLED — CR factory (veleroNamespace={}, "
                + "brandNamespaceSuffixes={}, ttl={})", veleroNamespace, suffixList, backupTtl);
        return new VeleroResourceFactory(veleroNamespace, suffixList, backupTtl);
    }

    /** The REAL Velero effector — wired ONLY when the flag is true. The foundation Noop is
     *  gated on the SAME flag's {@code false} branch (mutually exclusive), so EXACTLY ONE
     *  {@link BackupEffector} bean exists in every mode (the {@code TestReportsConfig} idiom). */
    @Bean
    @ConditionalOnProperty(name = "app.backups.effector.enabled", havingValue = "true")
    BackupEffector veleroBackupEffector(VeleroResourceFactory factory, BackupSetRepository sets) {
        VeleroBackupEffector.ClientFactory clientFactory = () -> new KubernetesClientBuilder().build();
        return new VeleroBackupEffector(clientFactory, factory, sets);
    }

    /** The REAL installed-services provider (per-brand ConfigMap filter) — wired ONLY when the
     *  flag is true. Falls back to the documented {@link StubRunningServiceProvider} catalog
     *  internally so the menu is never emptied. The foundation Stub is gated on the SAME flag's
     *  {@code false} branch, so EXACTLY ONE {@link RunningServiceProvider} exists in every mode. */
    @Bean
    @ConditionalOnProperty(name = "app.backups.effector.enabled", havingValue = "true")
    RunningServiceProvider configMapRunningServiceProvider(
            @Value("${app.backups.effector.installed-services-namespace:hugmesh-backend}") String namespace) {
        ConfigMapRunningServiceProvider.ClientFactory clientFactory =
                () -> new KubernetesClientBuilder().build();
        // The catalog vocabulary (kinds/labels) is the documented stub; this provider filters
        // it to the brand's installed-services ConfigMap.
        return new ConfigMapRunningServiceProvider(clientFactory, namespace,
                new StubRunningServiceProvider());
    }
}
