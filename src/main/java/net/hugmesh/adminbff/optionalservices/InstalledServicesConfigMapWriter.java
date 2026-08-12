package net.hugmesh.adminbff.optionalservices;

import java.util.Map;

/**
 * The seam that mirrors the desired-state into the {@code installed-services} ConfigMap
 * booleans ({@code hugmesh-policy} ns) — the greying/capability source the admin
 * console + the host's greying predicate read. A targeted merge-patch of ONLY the 12
 * controller-owned {@code /data/<slug>} keys (services.json + workloadConsole stay
 * ArgoCD-managed and untouched).
 *
 * <p>KEYSTONE: this only persists because {@code apps/16-reserved-prefixes-policy.yaml}
 * carries {@code ignoreDifferences} on those 12 data keys + {@code RespectIgnore
 * Differences=true}. See {@code docs/OPTIONAL-SERVICES.md §7.1}.
 *
 * <p>Two implementations gated by one dark flag:
 * {@code Fabric8InstalledServicesConfigMapWriter} (real) /
 * {@link NoopInstalledServicesConfigMapWriter} (cluster-less default).
 */
public interface InstalledServicesConfigMapWriter {

    /**
     * Merge-patch the {@code installed-services} ConfigMap so each managed slug's boolean
     * equals its {@code desired} value ({@code true}/{@code false} as the strings
     * {@code "true"}/{@code "false"}). Returns {@code true} on a successful apply.
     */
    boolean mirror(Map<String, Boolean> desired);

    /** True when this writer actually talks to a cluster. */
    boolean isReal();
}
