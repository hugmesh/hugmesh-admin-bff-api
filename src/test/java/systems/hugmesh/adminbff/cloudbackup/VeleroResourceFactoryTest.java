package systems.hugmesh.adminbff.cloudbackup;

import io.fabric8.kubernetes.api.model.GenericKubernetesResource;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The PURE Velero-CR builder behaviour — the heart of the brand-isolation guarantee, proven
 * WITHOUT a cluster. These assert the exact {@code velero.io/v1} {@code Backup}/{@code Restore}
 * CR shape the {@link VeleroBackupEffector} applies: a DOMAIN backup is doubly walled to its
 * brand (namespaces + {@code hugmesh.systems/domain} matchLabel) and can NEVER select another
 * brand; a TOTAL backup is cross-domain (no namespace/no domain selector); the destination is
 * wired by BackupStorageLocation name; and a Restore CR references the backup + re-applies the
 * brand wall.
 */
class VeleroResourceFactoryTest {

    private final VeleroResourceFactory factory =
            new VeleroResourceFactory("velero", List.of("be", "fe"), "720h0m0s");

    private static BackupSet set(BackupCloudScope scope, String domain, List<String> services,
                                 String destRef) {
        return new BackupSet("set-abc123", "domain-" + domain, 3L, scope, domain, "alice",
                services, BackupDestinationKind.OBJECT_STORE, destRef, null, null,
                BackupSet.STATUS_PENDING, Instant.now(), null, null);
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> spec(GenericKubernetesResource cr) {
        return (Map<String, Object>) cr.getAdditionalProperties().get("spec");
    }

    @SuppressWarnings("unchecked")
    private static Map<String, String> matchLabels(Map<String, Object> spec) {
        Map<String, Object> selector = (Map<String, Object>) spec.get("labelSelector");
        return selector == null ? null : (Map<String, String>) selector.get("matchLabels");
    }

    // ── DOMAIN scope: brand-walled namespaces + domain labelSelector ─────────────────────

    @Test
    void domainBackup_isWalledToBrandNamespaces_andDomainLabel() {
        GenericKubernetesResource cr = factory.backup(
                set(BackupCloudScope.DOMAIN, "brandx", List.of("postgres", "pvc"), "s3://bk-brandx"));

        assertThat(cr.getApiVersion()).isEqualTo("velero.io/v1");
        assertThat(cr.getKind()).isEqualTo("Backup");
        assertThat(cr.getMetadata().getNamespace()).isEqualTo("velero");

        Map<String, Object> spec = spec(cr);
        // namespaces: ONLY brandx's
        assertThat((List<String>) spec.get("includedNamespaces"))
                .containsExactly("brandx-be", "brandx-fe");
        // labelSelector: the hard brand wall
        assertThat(matchLabels(spec)).containsEntry("hugmesh.systems/domain", "brandx");
    }

    @Test
    void domainBackup_brandX_doesNotSelect_brandYNamespacesOrLabel() {
        GenericKubernetesResource brandX = factory.backup(
                set(BackupCloudScope.DOMAIN, "brandx", List.of("postgres"), "s3://bk-x"));
        GenericKubernetesResource brandY = factory.backup(
                set(BackupCloudScope.DOMAIN, "brandy", List.of("postgres"), "s3://bk-y"));

        List<String> xNs = (List<String>) spec(brandX).get("includedNamespaces");
        List<String> yNs = (List<String>) spec(brandY).get("includedNamespaces");

        // BRAND ISOLATION: brand-X's CR selects no brand-Y namespace, and vice versa.
        assertThat(xNs).containsExactly("brandx-be", "brandx-fe");
        assertThat(xNs).noneMatch(ns -> ns.startsWith("brandy-"));
        assertThat(yNs).noneMatch(ns -> ns.startsWith("brandx-"));

        // ... and the matchLabel is brand-specific (X never carries brandy, Y never brandx).
        assertThat(matchLabels(spec(brandX))).containsEntry("hugmesh.systems/domain", "brandx");
        assertThat(matchLabels(spec(brandX)).values()).doesNotContain("brandy");
        assertThat(matchLabels(spec(brandY))).containsEntry("hugmesh.systems/domain", "brandy");
        assertThat(matchLabels(spec(brandY)).values()).doesNotContain("brandx");

        // the CR is itself labelled with its brand (attribution)
        assertThat(brandX.getMetadata().getLabels())
                .containsEntry("hugmesh.systems/domain", "brandx");
        assertThat(brandY.getMetadata().getLabels())
                .containsEntry("hugmesh.systems/domain", "brandy");
    }

    @Test
    void domainBackup_sanitisesDomainSlugIntoNamespaces() {
        // a dotted/odd domain is slugified, never injected raw into a namespace name.
        GenericKubernetesResource cr = factory.backup(
                set(BackupCloudScope.DOMAIN, "Brand.Co", List.of("config"), "s3://b"));
        assertThat((List<String>) spec(cr).get("includedNamespaces"))
                .containsExactly("brand-co-be", "brand-co-fe");
        // the label keeps the original domain value (the attribution key the generator stamps).
        assertThat(matchLabels(spec(cr))).containsEntry("hugmesh.systems/domain", "Brand.Co");
    }

    // ── TOTAL scope: cross-domain capture (no wall) ──────────────────────────────────────

    @Test
    void totalBackup_hasNoNamespaceNorDomainSelector_capturingEveryBrand() {
        GenericKubernetesResource cr = factory.backup(
                set(BackupCloudScope.TOTAL, "default", List.of("postgres", "pvc"), "s3://total"));

        Map<String, Object> spec = spec(cr);
        // TOTAL = the whole cloud: no namespace restriction, no domain labelSelector.
        assertThat(spec).doesNotContainKey("includedNamespaces");
        assertThat(spec).doesNotContainKey("labelSelector");
        // and the CR is NOT brand-labelled (it is cross-domain).
        assertThat(cr.getMetadata().getLabels()).doesNotContainKey("hugmesh.systems/domain");
        // destination still wired.
        assertThat(spec.get("storageLocation")).isEqualTo("s3://total");
    }

    // ── destination -> BackupStorageLocation reference ───────────────────────────────────

    @Test
    void destinationRef_wiredAsStorageLocation_byName() {
        GenericKubernetesResource cr = factory.backup(
                set(BackupCloudScope.DOMAIN, "brandx", List.of("postgres"), "brandx-bsl"));
        assertThat(spec(cr).get("storageLocation")).isEqualTo("brandx-bsl");
    }

    @Test
    void blankDestinationRef_fallsBackToDefaultBsl() {
        GenericKubernetesResource cr = factory.backup(
                set(BackupCloudScope.DOMAIN, "brandx", List.of("postgres"), "   "));
        assertThat(spec(cr).get("storageLocation")).isEqualTo("default");
    }

    // ── per-service artifacts -> includedResources + volume capture ──────────────────────

    @Test
    void volumeBackedService_addsPvcAndPvResources_andSnapshotVolumesTrue() {
        GenericKubernetesResource cr = factory.backup(
                set(BackupCloudScope.DOMAIN, "brandx", List.of("matrix", "pvc"), "s3://b"));
        Map<String, Object> spec = spec(cr);
        assertThat((List<String>) spec.get("includedResources"))
                .contains("persistentvolumeclaims", "persistentvolumes");
        assertThat(spec.get("snapshotVolumes")).isEqualTo(true);
        assertThat(spec.get("defaultVolumesToFsBackup")).isEqualTo(true);
    }

    @Test
    void configBackedService_addsConfigmapsAndSecrets_andNoVolumeSnapshot() {
        GenericKubernetesResource cr = factory.backup(
                set(BackupCloudScope.DOMAIN, "brandx", List.of("config", "secrets"), "s3://b"));
        Map<String, Object> spec = spec(cr);
        assertThat((List<String>) spec.get("includedResources"))
                .contains("configmaps", "secrets");
        assertThat(spec.get("snapshotVolumes")).isEqualTo(false);
    }

    @Test
    void includedResources_areDeduplicated_andInsertionOrdered() {
        // two volume-backed + one config-backed -> pvc/pv once + configmaps/secrets once.
        List<String> res = VeleroResourceFactory.includedResources(
                List.of("matrix", "games", "config"));
        assertThat(res).containsExactly("persistentvolumeclaims", "persistentvolumes",
                "configmaps", "secrets");
    }

    // ── Restore CR ───────────────────────────────────────────────────────────────────────

    @Test
    void restore_referencesBackupByName_andReAppliesBrandWall() {
        BackupSet s = set(BackupCloudScope.DOMAIN, "brandx", List.of("pvc"), "s3://b");
        GenericKubernetesResource cr = factory.restore(s);

        assertThat(cr.getApiVersion()).isEqualTo("velero.io/v1");
        assertThat(cr.getKind()).isEqualTo("Restore");
        Map<String, Object> spec = spec(cr);
        // references the SAME backup CR name this version's backup() would build.
        assertThat(spec.get("backupName")).isEqualTo(factory.backupName(s));
        // brand wall re-applied (a DOMAIN restore can only target this brand).
        assertThat((List<String>) spec.get("includedNamespaces")).containsExactly("brandx-be", "brandx-fe");
        assertThat(matchLabels(spec)).containsEntry("hugmesh.systems/domain", "brandx");
        // PV restore on for a volume-backed set; conflict policy = update (desired-state).
        assertThat(spec.get("restorePVs")).isEqualTo(true);
        assertThat(spec.get("existingResourcePolicy")).isEqualTo("update");
    }

    @Test
    void totalRestore_hasNoBrandWall() {
        BackupSet s = set(BackupCloudScope.TOTAL, "default", List.of("postgres"), "s3://total");
        GenericKubernetesResource cr = factory.restore(s);
        Map<String, Object> spec = spec(cr);
        assertThat(spec.get("backupName")).isEqualTo(factory.backupName(s));
        assertThat(spec).doesNotContainKey("includedNamespaces");
        assertThat(spec).doesNotContainKey("labelSelector");
    }

    @Test
    void backupName_isDeterministic_perSetKeyAndVersion() {
        BackupSet s = set(BackupCloudScope.DOMAIN, "brandx", List.of("postgres"), "s3://b");
        assertThat(factory.backupName(s)).isEqualTo(factory.backupName(s)); // idempotent
        assertThat(factory.backupName(s)).contains("-v3");
    }
}
