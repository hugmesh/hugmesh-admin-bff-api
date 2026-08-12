package net.hugmesh.adminbff.argocd;

import reactor.core.publisher.Mono;

/**
 * The narrow ArgoCD Application admin seam the App-Store {@code AddService} effector
 * needs. The platform's existing ArgoCD usage is READ + single-SYNC only; provisioning
 * a NEW service (and tearing one down at end-of-lease) requires CREATE and DELETE of an
 * ArgoCD {@code Application}, which are NET-NEW.
 *
 * <p><b>GitOps note.</b> The platform's apply model is ArgoCD-syncs-from-Git (selfHeal is
 * law — there is never an "apply YAML" path; the games/workload reconcilers write a
 * desired-state ConfigMap / GitOps-PR intent and let ArgoCD reconcile). The
 * {@code Application} resource itself, however, is the GitOps ENTRY POINT — the thing that
 * tells ArgoCD which repo/path to watch for a service. Creating/deleting that one resource
 * via the ArgoCD API is the standard app-of-apps self-service registration leg (it points
 * at the descriptor repo the effector created; the descriptor's manifests are still
 * synced-from-Git, never applied directly).
 *
 * <p>TWO implementations gated by {@code app.appstore.effector.enabled} (default false →
 * ships dark): the real {@link RestArgoCdClient} (talks to the ArgoCD API server) and the
 * fail-closed {@link NoopArgoCdClient} (the default — every call is a logged no-op, dials
 * no ArgoCD). {@link #isReal()} is the runtime seam signal a test/caller can assert on.
 */
public interface ArgoCdClient {

    /**
     * Create-or-update an ArgoCD {@code Application} that watches {@code repoUrl}/{@code path}
     * on {@code targetRevision} and syncs into {@code destNamespace}. Idempotent: an
     * existing Application of the same {@code name} is updated (the App-Store may re-run the
     * effector). The Application is the GitOps entry point — its manifests are synced from
     * Git by ArgoCD, NOT applied here.
     *
     * @param name          the Application name (e.g. {@code <domain>-<service>})
     * @param repoUrl       the Git repo the descriptor lives in (in-cluster Forgejo/GitLab)
     * @param path          the path within the repo (e.g. {@code deploy/})
     * @param targetRevision the branch/tag/commit to track (e.g. {@code HEAD})
     * @param destNamespace the per-domain namespace the service deploys into
     * @return the created/updated Application name
     */
    Mono<String> createApplication(String name, String repoUrl, String path,
                                   String targetRevision, String destNamespace);

    /**
     * Delete an ArgoCD {@code Application} by name (cascade = the synced resources are
     * garbage-collected by ArgoCD). Idempotent teardown: an already-absent Application is
     * tolerated (a teardown re-run is safe). Returns true when the delete was issued (or the
     * app was already gone), false on a hard failure the caller should retry.
     */
    Mono<Boolean> deleteApplication(String name);

    /** True when this client actually talks to an ArgoCD API server (the runtime seam
     *  signal). The Noop default returns false so a ships-dark assertion is structural. */
    boolean isReal();
}
