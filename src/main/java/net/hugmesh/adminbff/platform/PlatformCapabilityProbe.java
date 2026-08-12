package net.hugmesh.adminbff.platform;

import java.util.List;

/**
 * The READ-ONLY runtime-discovery seam for the foundational-infra capabilities. ONE method
 * collects the four runtime probes (ArgoCD / Velero / build-node / generated-images presence)
 * into a {@link Result}.
 *
 * <p>Two implementations (config-only choice, the SAME pattern as {@code WorkloadClient} /
 * {@code JobLauncher}):
 * <ul>
 *   <li>{@link Fabric8PlatformCapabilityProbe} — the in-cluster fabric8 reader, wired ONLY when
 *       {@code app.platform-capabilities.k8s.enabled=true}. Every k8s call is READ-ONLY and
 *       FAIL-SAFE: it never mutates, and any error / no-access yields the capability {@code false}
 *       plus a warning rather than throwing.</li>
 *   <li>{@link NoopPlatformCapabilityProbe} — the DEFAULT (cluster-less dev/test/CI, or any
 *       deployment that has not enabled the seam). Reports every runtime capability ABSENT plus a
 *       warning that the probe is not wired — so the UI degrades gracefully and nothing is faked.</li>
 * </ul>
 *
 * <p>The probe NEVER reads the images table itself — image presence is a DB concern owned by the
 * controller (so a cluster-less deployment that still has an images table reports images
 * truthfully). The probe is strictly the k8s side.
 */
public interface PlatformCapabilityProbe {

    /** Whether this probe actually dials a cluster (the real fabric8 reader) or is the no-op. */
    boolean isReal();

    /** Collects the runtime probes. Always non-null; never throws (fail-safe per probe). */
    Result probe();

    /**
     * The runtime-probe outcome: the three k8s-discovered booleans plus any warnings explaining a
     * capability that could not be probed (k8s error / no client / no access). Image presence is
     * NOT here — the controller derives it from the images table.
     */
    record Result(boolean argocdPresent,
                  boolean veleroPresent,
                  boolean buildNodePresent,
                  List<String> warnings) {
        public Result {
            warnings = warnings == null ? List.of() : List.copyOf(warnings);
        }
    }
}
