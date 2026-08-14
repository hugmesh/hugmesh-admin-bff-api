package net.hugmesh.adminbff.cloudbackup;

import io.fabric8.kubernetes.api.model.GenericKubernetesResource;
import io.fabric8.kubernetes.api.model.GenericKubernetesResourceBuilder;
import net.hugmesh.adminbff.servicecatalog.PerServiceIdentity;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * PURE (no I/O) builder of the Velero ({@code velero.io/v1}) {@code Backup} / {@code Restore}
 * custom resources for a {@link BackupSet}. Separated from {@link VeleroBackupEffector} (which
 * does the cluster apply) so the CR SHAPE — the brand-isolation selectors, the per-service
 * resource scoping, the destination wiring — is unit-testable WITHOUT a cluster (the effector
 * just applies whatever this returns).
 *
 * <h3>Scope → selectors (BRAND ISOLATION)</h3>
 * <ul>
 *   <li><b>DOMAIN</b> — a per-brand backup. The CR is doubly walled to the brand:
 *     <ul>
 *       <li>{@code spec.includedNamespaces} = the brand's namespaces, derived from the
 *           domain slug ({@code <slug>-be} / {@code <slug>-fe} — the {@link PerServiceIdentity}
 *           {@code <domain>-be} convention), so Velero only walks THIS brand's namespaces;</li>
 *       <li>{@code spec.labelSelector.matchLabels} = {@code {hugmesh.net/domain: <domain>}}
 *           (the owner-chain attribution label the generator stamps, the same
 *           {@code WorkloadReadService.DOMAIN_LABEL} the workload console attributes by) — the
 *           HARD guarantee: even if a namespace were shared, a brand-X backup can only ever
 *           select resources LABELLED brand-X, never brand-Y's.</li>
 *     </ul>
 *   </li>
 *   <li><b>TOTAL</b> — the superadmin total-cloud backup. NO {@code includedNamespaces} and NO
 *       domain {@code labelSelector}, so Velero captures EVERY brand's state at once (the infra
 *       control plane). (Velero's own {@code excludedNamespaces} install-default still excludes
 *       {@code kube-system} etc.; we do not re-add them here.)</li>
 * </ul>
 *
 * <h3>Per-service artifacts → resource scoping</h3>
 * The selected running services ({@link BackupSet#services()}) map to
 * {@code spec.includedResources}: a DB-backed service contributes no extra resource kinds
 * (its dump is the worker's job and config), a volume-backed service adds
 * {@code persistentvolumeclaims} + {@code persistentvolumes} so Velero snapshots its PVs, and a
 * config service adds {@code configmaps} + {@code secrets}. The union is emitted (deduplicated,
 * insertion-ordered) so the CR is byte-stable across runs.
 *
 * <h3>Destination → BackupStorageLocation REFERENCE</h3>
 * {@code spec.storageLocation} = the destination ref BY NAME (the Velero
 * {@code BackupStorageLocation} the generator/ESO leg provisions). This factory NEVER mints
 * credentials and NEVER creates the BSL — it only references it by name, exactly as the
 * foundation's {@code destination_ref} / {@code secret_ref} contract requires (refs only, never
 * the bytes).
 */
public final class VeleroResourceFactory {

    /** The Velero CR API group/version (the install default). */
    public static final String API_VERSION = "velero.io/v1";
    public static final String KIND_BACKUP = "Backup";
    public static final String KIND_RESTORE = "Restore";

    /** The owner-chain brand attribution label (mirrors
     *  {@code WorkloadReadService.DOMAIN_LABEL}) — the brand-isolation matchLabel. */
    public static final String DOMAIN_LABEL = "hugmesh.net/domain";

    /** A label stamped on every CR this factory builds so the catalog row and the CR can be
     *  correlated (and so a sweep can find the CRs a set produced). NOT a selector. */
    public static final String SET_ID_LABEL = "hugmesh.net/backup-set-id";
    public static final String SET_KEY_LABEL = "hugmesh.net/backup-set-key";

    /** The namespace Velero (and therefore its Backup/Restore CRs) lives in. */
    private final String veleroNamespace;
    /** The per-brand namespace suffixes a DOMAIN backup includes ({@code be}, {@code fe}, ...). */
    private final List<String> brandNamespaceSuffixes;
    /** Velero TTL for the backup (e.g. {@code 720h0m0s}); null/blank omits it (Velero default). */
    private final String backupTtl;

    public VeleroResourceFactory(String veleroNamespace, List<String> brandNamespaceSuffixes,
                                 String backupTtl) {
        this.veleroNamespace = (veleroNamespace == null || veleroNamespace.isBlank())
                ? "velero" : veleroNamespace.trim();
        this.brandNamespaceSuffixes = (brandNamespaceSuffixes == null || brandNamespaceSuffixes.isEmpty())
                ? List.of("be", "fe") : List.copyOf(brandNamespaceSuffixes);
        this.backupTtl = (backupTtl == null || backupTtl.isBlank()) ? null : backupTtl.trim();
    }

    public String veleroNamespace() {
        return veleroNamespace;
    }

    /** The Velero {@code Backup} CR name for a set ({@code hugmesh-bk-<setKey>-v<version>}),
     *  DNS-safe. Deterministic so a re-run of the same set version is idempotent (a re-apply,
     *  not a duplicate). */
    public String backupName(BackupSet set) {
        return "hugmesh-bk-" + PerServiceIdentity.slug(set.setKey()) + "-v" + set.version();
    }

    /** The Velero {@code Restore} CR name for a set
     *  ({@code hugmesh-rs-<setKey>-v<version>-<shortId>}). The short id keeps repeated
     *  restores of the SAME version distinct (a restore is not idempotent like a backup). */
    public String restoreName(BackupSet set) {
        String shortId = set.id() == null ? "x"
                : PerServiceIdentity.slug(set.id()).replace("-", "");
        if (shortId.length() > 8) {
            shortId = shortId.substring(0, 8);
        }
        return "hugmesh-rs-" + PerServiceIdentity.slug(set.setKey()) + "-v" + set.version()
                + "-" + shortId;
    }

    /** Build the Velero {@code Backup} CR for the set. */
    public GenericKubernetesResource backup(BackupSet set) {
        Map<String, Object> spec = new LinkedHashMap<>();

        // ── brand isolation: namespaces + domain labelSelector (DOMAIN only) ──
        if (!set.isTotal()) {
            List<String> namespaces = brandNamespaces(set.domain());
            if (!namespaces.isEmpty()) {
                spec.put("includedNamespaces", namespaces);
            }
            spec.put("labelSelector", matchLabels(Map.of(DOMAIN_LABEL, set.domain())));
        }
        // TOTAL: no includedNamespaces, no domain labelSelector -> cross-domain capture.

        // ── per-service artifacts -> includedResources ──
        List<String> includedResources = includedResources(set.services());
        if (!includedResources.isEmpty()) {
            spec.put("includedResources", includedResources);
        }

        // ── PV snapshotting: any pv_snapshot service implies volume capture ──
        boolean anyVolume = set.services() != null && set.services().stream()
                .anyMatch(VeleroResourceFactory::isVolumeBacked);
        spec.put("snapshotVolumes", anyVolume);
        spec.put("defaultVolumesToFsBackup", anyVolume);

        // ── destination -> BackupStorageLocation reference (by NAME; never credentials) ──
        spec.put("storageLocation", storageLocationRef(set));

        if (backupTtl != null) {
            spec.put("ttl", backupTtl);
        }

        return cr(KIND_BACKUP, backupName(set), set, spec);
    }

    /** Build the Velero {@code Restore} CR for the set. References the backup CR for this
     *  version BY NAME, and re-applies the SAME brand-namespace wall (a DOMAIN restore can only
     *  ever target this brand's namespaces). DESTRUCTIVE: this overwrites live state, which is
     *  why the restore path is step-up-gated upstream in the foundation controller. */
    public GenericKubernetesResource restore(BackupSet set) {
        Map<String, Object> spec = new LinkedHashMap<>();
        spec.put("backupName", backupName(set));

        if (!set.isTotal()) {
            List<String> namespaces = brandNamespaces(set.domain());
            if (!namespaces.isEmpty()) {
                spec.put("includedNamespaces", namespaces);
            }
            spec.put("labelSelector", matchLabels(Map.of(DOMAIN_LABEL, set.domain())));
        }

        boolean anyVolume = set.services() != null && set.services().stream()
                .anyMatch(VeleroResourceFactory::isVolumeBacked);
        spec.put("restorePVs", anyVolume);
        // Update-in-place on conflict (the desired-state restore), not a hard fail.
        spec.put("existingResourcePolicy", "update");

        return cr(KIND_RESTORE, restoreName(set), set, spec);
    }

    // ── helpers ───────────────────────────────────────────────────────────────

    private GenericKubernetesResource cr(String kind, String name, BackupSet set,
                                         Map<String, Object> spec) {
        Map<String, String> labels = new LinkedHashMap<>();
        labels.put("app.kubernetes.io/part-of", "hugmesh.net");
        labels.put("app.kubernetes.io/managed-by", "hugmesh-admin-bff");
        if (set.id() != null) {
            labels.put(SET_ID_LABEL, PerServiceIdentity.slug(set.id()));
        }
        if (set.setKey() != null) {
            labels.put(SET_KEY_LABEL, PerServiceIdentity.slug(set.setKey()));
        }
        // The brand label is stamped on the CR itself too (DOMAIN scope), so the CR is
        // attributable to its brand even before it selects anything.
        if (!set.isTotal()) {
            labels.put(DOMAIN_LABEL, set.domain());
        }

        GenericKubernetesResource cr = new GenericKubernetesResourceBuilder()
                .withApiVersion(API_VERSION)
                .withKind(kind)
                .withNewMetadata()
                .withName(name)
                .withNamespace(veleroNamespace)
                .withLabels(labels)
                .endMetadata()
                .build();
        cr.setAdditionalProperty("spec", spec);
        return cr;
    }

    /** The brand's namespaces for a DOMAIN backup — {@code <slug>-<suffix>} for each configured
     *  suffix. The slug is the {@link PerServiceIdentity} DNS-safe slug, so a malformed domain
     *  can never inject into a namespace name. */
    List<String> brandNamespaces(String domain) {
        String slug = PerServiceIdentity.slug(domain);
        List<String> out = new ArrayList<>();
        for (String suffix : brandNamespaceSuffixes) {
            String s = PerServiceIdentity.slug(suffix);
            out.add(slug + "-" + s);
        }
        return out;
    }

    /** The Velero {@code spec.labelSelector} object ({@code {matchLabels: {...}}}). */
    private static Map<String, Object> matchLabels(Map<String, String> labels) {
        Map<String, Object> selector = new LinkedHashMap<>();
        selector.put("matchLabels", new LinkedHashMap<>(labels));
        return selector;
    }

    /** The destination ref: the Velero {@code BackupStorageLocation} name. For an object-store
     *  destination this is the BSL the generator/ESO leg provisions (the {@code destination_ref}
     *  / {@code secret_ref} pair); for node-storage it is the BSL backed by the FDE volume. We
     *  reference it by name only — NEVER create it, NEVER carry credentials. A blank ref falls
     *  back to {@code default} (Velero's default BSL) so the CR is always valid. */
    private static String storageLocationRef(BackupSet set) {
        String ref = set.destinationRef();
        return (ref == null || ref.isBlank()) ? "default" : ref.trim();
    }

    /** The union of Velero resource kinds the selected services need, deduplicated +
     *  insertion-ordered. Empty when no service maps to a specific kind (Velero then captures
     *  everything in the selected namespaces/labels). */
    static List<String> includedResources(List<String> services) {
        List<String> out = new ArrayList<>();
        if (services == null) {
            return out;
        }
        for (String svc : services) {
            if (svc == null || svc.isBlank()) {
                continue;
            }
            String s = svc.toLowerCase();
            if (isVolumeBacked(s)) {
                addDistinct(out, "persistentvolumeclaims");
                addDistinct(out, "persistentvolumes");
            }
            if (isConfigBacked(s)) {
                addDistinct(out, "configmaps");
                addDistinct(out, "secrets");
            }
        }
        return out;
    }

    private static void addDistinct(List<String> list, String v) {
        if (!list.contains(v)) {
            list.add(v);
        }
    }

    /** A volume-backed service (pv_snapshot kind in the foundation menu): etcd / pvc / matrix /
     *  games / tube / owncast. */
    private static boolean isVolumeBacked(String service) {
        if (service == null) {
            return false;
        }
        String s = service.toLowerCase();
        return s.equals("etcd") || s.equals("pvc") || s.equals("matrix")
                || s.equals("games") || s.equals("tube") || s.equals("owncast");
    }

    /** A config-backed service (config kind in the foundation menu): secrets / config. */
    private static boolean isConfigBacked(String service) {
        if (service == null) {
            return false;
        }
        String s = service.toLowerCase();
        return s.equals("secrets") || s.equals("config");
    }
}
