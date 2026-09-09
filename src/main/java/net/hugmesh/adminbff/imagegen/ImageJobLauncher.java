package net.hugmesh.adminbff.imagegen;

import reactor.core.publisher.Mono;

/**
 * The seam that submits the rendered image-gen Job manifest to Kubernetes — the
 * image-generation mirror of
 * {@link net.hugmesh.adminbff.testreports.JobLauncher}.
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
     * Apply the rendered Job YAML and emit the created Job's metadata.name.
     *
     * <p>Reactive by contract, mirroring
     * {@link net.hugmesh.adminbff.testreports.JobLauncher#apply}: the fabric8 implementation
     * does blocking I/O, so the seam returns a {@code Mono} that carries its own
     * {@code boundedElastic} offload instead of making every call site remember to wrap it.
     * A cluster-side rejection arrives as an {@code onError} carrying the 502
     * {@code ApiException} (it used to be thrown synchronously).
     *
     * @param manifest the fully-substituted Job YAML
     * @param buildId  the image_build id (for the synthetic no-op name / logging)
     * @return the applied Job name (never null)
     */
    Mono<String> apply(String manifest, String buildId);

    /** True when this launcher actually talks to a cluster (the runtime seam signal). */
    boolean isReal();
}
