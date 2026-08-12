package net.hugmesh.adminbff.workload;

import java.time.Instant;

/**
 * A WORKLOAD CONSOLE GitOps-PR INTENT — the OUTBOX row for a GitOps-authoritative lifecycle
 * verb. The GitOps verbs (scale/deploy/service-removal/export-manifest) are NOT live k8s
 * mutations (selfHeal would revert them); they are recorded here as a desired-state intent
 * and SHIP DARK like {@code service_deployment} (102): the ArgoCD-PR effect is STUBBED/LOGGED
 * by {@link WorkloadGitOpsEmitter}. The UI surfaces the pending intent ("pending sync").
 * There is NEVER an "apply YAML" path — ArgoCD-sync-of-Git is the only apply.
 */
public record WorkloadConsoleIntent(
        String id,
        String kind,
        String namespace,
        String workload,
        String imageRef,
        Integer replicas,
        String requestedBy,
        Instant requestedAt,
        String domain,
        String propagationState,
        long generation) {

    public static final String KIND_SCALE = "SCALE";
    public static final String KIND_DEPLOY = "DEPLOY";
    public static final String KIND_REMOVE_SERVICE = "REMOVE_SERVICE";
    public static final String KIND_EXPORT_MANIFEST = "EXPORT_MANIFEST";

    public static final String PROP_PENDING = "pending";
}
