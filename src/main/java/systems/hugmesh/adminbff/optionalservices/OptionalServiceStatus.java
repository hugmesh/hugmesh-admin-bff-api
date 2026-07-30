package systems.hugmesh.adminbff.optionalservices;

import java.time.Instant;
import java.util.List;

/**
 * The fabric8-free desired {@code .status} the reconciler computes for one
 * {@code OptionalService} CR and hands to {@link OptionalServiceClient#updateStatus}.
 * Matches the CRD status schema (observedGeneration / installed / phase /
 * applicationName / lastReconcileTime / conditions).
 */
public record OptionalServiceStatus(
        long observedGeneration,
        boolean installed,
        String phase,
        String applicationName,
        Instant lastReconcileTime,
        List<Condition> conditions) {

    /** Coarse lifecycle phases (mirrors the CRD status.phase enum). */
    public static final String PHASE_PENDING = "Pending";
    public static final String PHASE_RECONCILING = "Reconciling";
    public static final String PHASE_ENABLED = "Enabled";
    public static final String PHASE_DISABLED = "Disabled";
    public static final String PHASE_DEGRADED = "Degraded";

    /** Standard metav1.Condition subset (type/status/reason/message + bookkeeping). */
    public record Condition(
            String type,
            String status,          // "True" | "False" | "Unknown"
            String reason,
            String message,
            long observedGeneration,
            Instant lastTransitionTime) {

        public static final String TYPE_RECONCILED = "Reconciled";
        public static final String TYPE_APPLICATIONSET_PATCHED = "ApplicationSetPatched";
        public static final String TYPE_CONFIGMAP_MIRRORED = "ConfigMapMirrored";
    }
}
