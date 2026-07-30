package systems.hugmesh.adminbff.imagegen;

/**
 * The seam that submits the rendered image-gen Job manifest to Kubernetes — the
 * image-generation mirror of
 * {@link systems.hugmesh.adminbff.testreports.JobLauncher}.
 *
 * <p>Two implementations, gated mutually-exclusively by {@code imagegen.launch.enabled}
 * (see {@link ImageGenConfig}):
 * <ul>
 *   <li>{@link Fabric8ImageJobLauncher} — applies the manifest with the fabric8
 *       {@code KubernetesClient}, wired ONLY when {@code imagegen.launch.enabled=true};</li>
 *   <li>{@link NoopImageJobLauncher} — the cluster-less default (SHIPS DARK), so the
 *       trigger &rarr; ingest &rarr; SSE &rarr; download contract is fully exercisable
 *       without a live cluster and without ever launching a real build.</li>
 * </ul>
 *
 * <p>Returning the applied Job's name lets the orchestrator record it on the
 * {@code image_build} row for later log-tail / reap.
 */
public interface ImageJobLauncher {

    /**
     * Apply the rendered Job YAML and return the created Job's metadata.name.
     *
     * @param manifest the fully-substituted Job YAML
     * @param buildId  the image_build id (for the synthetic no-op name / logging)
     * @return the applied Job name (never null)
     */
    String apply(String manifest, String buildId);

    /** True when this launcher actually talks to a cluster (the runtime seam signal). */
    boolean isReal();
}
