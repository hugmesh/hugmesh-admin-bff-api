package net.hugmesh.adminbff.optionalservices;

import java.util.Map;

/**
 * The seam that makes admin-bff the SINGLE writer of the {@code optional-services}
 * ApplicationSet's inline list-generator element {@code installed} flags
 * ({@code apps/13a-optional-services.yaml}, {@code /spec/generators/0/list/elements}).
 * A targeted read-modify-write flips {@code installed} on the element whose {@code slug}
 * matches each desired entry; ArgoCD's ApplicationSet controller then creates/prunes
 * {@code optional-<slug>} via the {@code installed:"true"} selector.
 *
 * <p>KEYSTONE: this only persists because the ArgoCD recurse roots
 * ({@code app-of-apps.yaml} + {@code apps/00-app-of-apps-waved.yaml}) carry
 * {@code ignoreDifferences} on that elements path + {@code RespectIgnoreDifferences=true}
 * — otherwise selfHeal reverts the write. See {@code docs/OPTIONAL-SERVICES.md §7.1}.
 *
 * <p>Two implementations gated by one dark flag (the node-storage writer idiom):
 * {@code Fabric8OptionalServiceApplicationSetPatcher} (real) /
 * {@link NoopOptionalServiceApplicationSetPatcher} (cluster-less default).
 */
public interface OptionalServiceApplicationSetPatcher {

    /**
     * Reconcile the {@code installed} flag of every element whose {@code slug} is a key
     * of {@code desired} ({@code true -> "true"}, {@code false -> "false"}); elements
     * whose slug is absent from {@code desired} are left untouched. Returns {@code true}
     * on a successful apply (or a no-op when nothing changed).
     */
    boolean apply(Map<String, Boolean> desired);

    /** True when this patcher actually talks to a cluster. */
    boolean isReal();
}
