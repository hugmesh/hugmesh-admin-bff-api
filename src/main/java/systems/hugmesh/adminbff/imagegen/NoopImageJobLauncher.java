package systems.hugmesh.adminbff.imagegen;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Cluster-less {@link ImageJobLauncher} — the DEFAULT whenever
 * {@code imagegen.launch.enabled} is not {@code true} (dev / test / CI, and any
 * deployment that has not opted the real launcher in). SHIPS DARK: it logs the apply
 * intent and returns a synthetic Job name so the trigger &rarr; ingest &rarr; SSE
 * &rarr; download contract is exercisable without a live cluster and WITHOUT ever
 * launching a real image build. The REAL launcher
 * ({@link Fabric8ImageJobLauncher}) exists and is one config flag away.
 */
public class NoopImageJobLauncher implements ImageJobLauncher {

    private static final Logger log = LoggerFactory.getLogger(NoopImageJobLauncher.class);

    @Override
    public String apply(String manifest, String buildId) {
        log.info("[imagegen] (seam) would apply image-gen k8s Job for build {} ({} bytes); "
                + "set imagegen.launch.enabled=true to apply for real", buildId, manifest.length());
        return "hugmesh-image-gen-" + buildId;
    }

    @Override
    public boolean isReal() {
        return false;
    }
}
