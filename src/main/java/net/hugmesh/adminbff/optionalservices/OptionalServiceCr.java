package net.hugmesh.adminbff.optionalservices;

/**
 * A fabric8-free projection of ONE {@code OptionalService}
 * ({@code platform.hugmesh.systems/v1alpha1}) custom resource — the runtime
 * desired-state object for a slug. Mirrors the {@code cloudbackup.VeleroCr} pattern:
 * the {@link OptionalServiceClient} reads the CRs via the fabric8 generic-resource API
 * (the platform's established idiom — no typed {@code CustomResource} model exists in
 * the repo) and hands the reconciler this immutable projection.
 *
 * @param name             the resource name (== slug for the seed CRs)
 * @param namespace        the CR namespace (devops)
 * @param slug             spec.slug — the optional-service slug
 * @param enabled          spec.enabled — the runtime toggle
 * @param reason           spec.reason (audit; may be null)
 * @param requestedBy      spec.requestedBy (audit; may be null)
 * @param generation       metadata.generation (for status.observedGeneration)
 * @param resourceVersion  metadata.resourceVersion (optimistic-concurrency token for status writes)
 */
public record OptionalServiceCr(
        String name,
        String namespace,
        String slug,
        boolean enabled,
        String reason,
        String requestedBy,
        long generation,
        String resourceVersion) {
}
