package net.hugmesh.adminbff.imagegen;

import io.fabric8.kubernetes.client.KubernetesClientBuilder;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Wires the {@link ImageJobLauncher} the {@link ImageBuildOrchestrator} uses to launch the
 * image-gen Job. Logic-mirror of
 * {@link net.hugmesh.adminbff.testreports.TestReportsConfig}, with DISTINCT config
 * keys ({@code imagegen.launch.*}) so it never collides with {@code testreports.launch.*},
 * {@code app.device-terminal.*}, or {@code app.backups.*}.
 *
 * <p><b>SHIPS DARK by default.</b> The {@code imagegen.launch.enabled} flag defaults FALSE,
 * so a cluster-less dev/test/CI run — and any production deployment that has NOT explicitly
 * opted in — boots against the {@link NoopImageJobLauncher} and NEVER launches a real image
 * build. The REAL {@link Fabric8ImageJobLauncher} is wired ONLY when the flag is true. The
 * fabric8 {@code KubernetesClient} is built LAZILY (per apply, via the supplier) so a missing
 * in-cluster context never fails BFF boot — only an actual launch attempt touches the API
 * server.
 *
 * <p>The two {@link ImageJobLauncher} beans are gated by the <em>same</em>
 * {@code imagegen.launch.enabled} property with mutually-exclusive values — the real one on
 * {@code havingValue="true"} and the no-op one on {@code havingValue="false",
 * matchIfMissing=true} — so EXACTLY ONE {@link ImageJobLauncher} is registered in every mode.
 * (A {@code @ConditionalOnMissingBean} gate cannot guarantee this within a single
 * {@code @Configuration}: the no-op bean method is evaluated BEFORE the real bean is
 * registered, so the missing-bean condition matches and BOTH register when the flag is true —
 * a {@code NoUniqueBeanDefinitionException} at injection into {@link ImageBuildOrchestrator},
 * which bricks launch-enabled deploys.) This invariant is pinned by an
 * {@code ApplicationContextRunner} test.
 *
 * <p>The launch namespace defaults to {@code hugmesh-backend} (the BFF's own namespace,
 * where the {@code image-gen} ServiceAccount + RBAC live) and is overridable for a
 * branded/relocated deployment.
 */
@Configuration(proxyBeanMethods = false)
public class ImageGenConfig {

    /**
     * The mesh SUPERDOMAIN suffix (worklist redesign item 5). A mesh build's superdomain — the
     * orchestration domain all mesh nodes join — is NON_ARGV (rides the mesh manifest + the KEYS
     * MagicDNS channel, NEVER a builder flag / Job env / go-live-flippable value). When a build
     * carries no operator {@code superdomain} override, the effective value is derived
     * {@code <brand>.<suffix>} — byte-for-byte with the generator's {@code effective_superdomain}
     * ({@code <brand>.internal}). Bound from {@code imagegen.mesh.superdomain-suffix} (default
     * {@code internal}); the field initializer keeps a plain {@code new ImageGenConfig()} (unit
     * tests) at the same default without a Spring PropertySource.
     */
    @Value("${imagegen.mesh.superdomain-suffix:internal}")
    String superdomainSuffix = "internal";

    /** The effective superdomain suffix, never blank (falls back to {@code internal}). */
    public String superdomainSuffix() {
        return (superdomainSuffix == null || superdomainSuffix.isBlank()) ? "internal" : superdomainSuffix;
    }

    /** Cluster-less default (SHIPS DARK) — used whenever the real launcher is not enabled. */
    @Bean
    @ConditionalOnProperty(name = "imagegen.launch.enabled", havingValue = "false", matchIfMissing = true)
    ImageJobLauncher noopImageJobLauncher() {
        return new NoopImageJobLauncher();
    }

    /** The REAL fabric8 launcher — wired only when imagegen.launch.enabled=true. */
    @Bean
    @ConditionalOnProperty(name = "imagegen.launch.enabled", havingValue = "true")
    ImageJobLauncher fabric8ImageJobLauncher(
            @Value("${imagegen.launch.namespace:hugmesh-backend}") String namespace) {
        // Lazy client: built on first apply, not at boot — a transient API-server outage must
        // not brick the BFF. The in-cluster ServiceAccount / kubeconfig is auto-discovered by
        // the fabric8 default config.
        Fabric8ImageJobLauncher.ClientFactory factory = () -> new KubernetesClientBuilder().build();
        return new Fabric8ImageJobLauncher(factory, namespace);
    }
}
