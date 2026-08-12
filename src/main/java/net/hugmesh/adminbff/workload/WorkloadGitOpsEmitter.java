package net.hugmesh.adminbff.workload;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;
import net.hugmesh.commons.security.PrincipalDomain;

/**
 * The GitOps-PR INTENT emitter for the GitOps-authoritative lifecycle verbs (scale / deploy /
 * service-removal / export-manifest). selfHeal is law: these are NOT live k8s mutations
 * (ArgoCD would revert spec drift in seconds) — they are recorded as a desired-state
 * {@code workload_console_intent} row and the UI surfaces the "pending sync". This SHIPS
 * DARK exactly like {@code ServiceDeploymentExpiryAction}: the ACTUAL ArgoCD-PR open /
 * manifest write is STUBBED + LOGGED here (no git/GitLab/ArgoCD call), to be wired in a later
 * GitOps-effector phase. There is NEVER an "apply YAML" path — ArgoCD-sync-of-Git is the only
 * apply.
 *
 * <h3>Deploy provenance (DECISION 7)</h3>
 * A DEPLOY intent's image MUST be digest-pinned own-registry-only — {@link #requireDigest}
 * rejects a tag-only ref at PR-gen time (the DB CHECK is the PG backstop, the Kyverno
 * verifyImages/allowed-registries admission is the cluster backstop the generator emits).
 */
@Service
public class WorkloadGitOpsEmitter {

    private static final Logger log = LoggerFactory.getLogger(WorkloadGitOpsEmitter.class);

    private final WorkloadConsoleIntentRepository intents;

    public WorkloadGitOpsEmitter(WorkloadConsoleIntentRepository intents) {
        this.intents = intents;
    }

    /** SCALE = replicas override via a PR (start/stop). */
    public Mono<WorkloadConsoleIntent> scale(String namespace, String workload, int replicas,
                                             PrincipalDomain scope, String requestedBy) {
        if (replicas < 0) {
            return Mono.error(new IllegalArgumentException("replicas must be >= 0"));
        }
        WorkloadConsoleIntent draft = new WorkloadConsoleIntent(null, WorkloadConsoleIntent.KIND_SCALE,
                namespace, workload, null, replicas, requestedBy, null, scope.domain(),
                WorkloadConsoleIntent.PROP_PENDING, 0);
        return store(draft);
    }

    /** DEPLOY = catalog -> PR, digest-pinned own-registry only. */
    public Mono<WorkloadConsoleIntent> deploy(String namespace, String workload, String imageRef,
                                              PrincipalDomain scope, String requestedBy) {
        try {
            requireDigest(imageRef);
        } catch (IllegalArgumentException e) {
            return Mono.error(e);
        }
        WorkloadConsoleIntent draft = new WorkloadConsoleIntent(null, WorkloadConsoleIntent.KIND_DEPLOY,
                namespace, workload, imageRef, null, requestedBy, null, scope.domain(),
                WorkloadConsoleIntent.PROP_PENDING, 0);
        return store(draft);
    }

    /** REMOVE_SERVICE = Application-delete PR (strong-confirm enforced by the controller). */
    public Mono<WorkloadConsoleIntent> removeService(String namespace, String workload,
                                                     PrincipalDomain scope, String requestedBy) {
        WorkloadConsoleIntent draft = new WorkloadConsoleIntent(null,
                WorkloadConsoleIntent.KIND_REMOVE_SERVICE, namespace, workload, null, null,
                requestedBy, null, scope.domain(), WorkloadConsoleIntent.PROP_PENDING, 0);
        return store(draft);
    }

    /** EXPORT_MANIFEST = export current state -> PR (generate kube). */
    public Mono<WorkloadConsoleIntent> exportManifest(String namespace, String workload,
                                                      PrincipalDomain scope, String requestedBy) {
        WorkloadConsoleIntent draft = new WorkloadConsoleIntent(null,
                WorkloadConsoleIntent.KIND_EXPORT_MANIFEST, namespace, workload, null, null,
                requestedBy, null, scope.domain(), WorkloadConsoleIntent.PROP_PENDING, 0);
        return store(draft);
    }

    private Mono<WorkloadConsoleIntent> store(WorkloadConsoleIntent draft) {
        return intents.maxGeneration()
                .flatMap(maxGen -> intents.insert(draft, maxGen + 1))
                .doOnNext(i -> log.warn(
                        "[workload-gitops] INTENT recorded (SHIPS DARK — no ArgoCD/PR effect yet) "
                        + "kind={} ns={} workload={} by={}",
                        i.kind(), i.namespace(), i.workload(), i.requestedBy()));
    }

    /** Reject any image ref that is not digest-pinned (own-registry digest-only provenance). */
    public static void requireDigest(String imageRef) {
        if (imageRef == null || imageRef.isBlank()) {
            throw new IllegalArgumentException("image ref is required");
        }
        if (!imageRef.contains("@sha256:")) {
            throw new IllegalArgumentException(
                    "deploy image must be digest-pinned (own-registry @sha256:...); tags are rejected");
        }
    }
}
