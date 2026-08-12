package net.hugmesh.adminbff.testreports;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Cluster-less {@link JobLauncher} — the default whenever
 * {@code testreports.launch.enabled} is not {@code true} (dev / test / slice runs,
 * and any deployment that has not opted the real launcher in). It logs the apply
 * intent and returns a synthetic Job name so the start &rarr; ingest &rarr; SSE
 * &rarr; durable-status contract is exercisable without a live cluster — the same
 * "documented seam, no-op here" discipline the backup orchestrator uses, except the
 * REAL launcher ({@link Fabric8JobLauncher}) exists and is one config flag away.
 */
public class NoopJobLauncher implements JobLauncher {

    private static final Logger log = LoggerFactory.getLogger(NoopJobLauncher.class);

    @Override
    public String apply(String manifest, String runId) {
        log.info("[test-reports] (seam) would apply test-runner k8s Job for run {} ({} bytes); "
                + "set testreports.launch.enabled=true to apply for real", runId, manifest.length());
        return "hugmesh-test-runner-" + runId;
    }

    @Override
    public boolean isReal() {
        return false;
    }
}
