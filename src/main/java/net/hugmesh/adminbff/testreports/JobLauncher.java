package net.hugmesh.adminbff.testreports;

/**
 * The seam that submits the rendered test-runner Job manifest to Kubernetes.
 *
 * <p>This is the part the design says must be BUILT for real (the backup
 * {@code BackupOrchestrator.applyJob} is a documented no-op — "reuse the backup
 * orchestrator k8s-launch pattern but BUILD the real launch"). Two implementations:
 * <ul>
 *   <li>{@link Fabric8JobLauncher} — applies the manifest with the fabric8
 *       {@code KubernetesClient} (already on the classpath via the
 *       spring-cloud-kubernetes leader starter), gated by
 *       {@code testreports.launch.enabled=true};</li>
 *   <li>{@link NoopJobLauncher} — the cluster-less default for dev/test/slice runs,
 *       so the start &rarr; ingest &rarr; SSE &rarr; durable-status contract is fully
 *       exercisable without a live cluster.</li>
 * </ul>
 *
 * <p>Returning the applied Job's name lets the orchestrator record it on the
 * {@code test_run} row for later log-tail / reap. A no-op launcher returns a
 * synthetic {@code <runId>}-shaped name so the contract is uniform.
 */
public interface JobLauncher {

    /**
     * Apply the rendered Job YAML and return the created Job's metadata.name.
     *
     * @param manifest the fully-substituted Job YAML
     * @param runId    the test_run id (for the synthetic no-op name / logging)
     * @return the applied Job name (never null)
     */
    String apply(String manifest, String runId);

    /** True when this launcher actually talks to a cluster (the runtime seam signal). */
    boolean isReal();
}
