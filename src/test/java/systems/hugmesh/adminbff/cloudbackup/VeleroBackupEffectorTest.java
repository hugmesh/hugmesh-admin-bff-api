package systems.hugmesh.adminbff.cloudbackup;

import io.fabric8.kubernetes.api.model.GenericKubernetesResource;
import io.fabric8.kubernetes.client.KubernetesClient;
import io.fabric8.kubernetes.client.KubernetesClientException;
import io.fabric8.kubernetes.client.dsl.MixedOperation;
import io.fabric8.kubernetes.client.dsl.Resource;
import io.fabric8.kubernetes.client.dsl.base.ResourceDefinitionContext;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.time.Instant;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * The REAL Velero effector behaviour with a MOCKED fabric8 {@link KubernetesClient} — NEVER a
 * real cluster. Asserts the effector applies EXACTLY the CR the factory builds (the brand-walled
 * Backup, the Restore), drives the catalog set status forward (RUNNING on success, FAILED on a
 * cluster rejection), and that a cluster failure is swallowed (the request is not a 500).
 */
class VeleroBackupEffectorTest {

    @SuppressWarnings("rawtypes")
    private MixedOperation mixedOp;
    @SuppressWarnings("rawtypes")
    private io.fabric8.kubernetes.client.dsl.NonNamespaceOperation nsOp;
    private KubernetesClient client;
    private BackupSetRepository sets;
    private VeleroResourceFactory factory;
    private VeleroBackupEffector effector;
    private Resource<GenericKubernetesResource> resourceOp;

    @BeforeEach
    @SuppressWarnings({"unchecked", "rawtypes"})
    void setUp() {
        client = mock(KubernetesClient.class);
        mixedOp = mock(MixedOperation.class);
        nsOp = mock(io.fabric8.kubernetes.client.dsl.NonNamespaceOperation.class);
        resourceOp = mock(Resource.class);
        sets = mock(BackupSetRepository.class);
        factory = new VeleroResourceFactory("velero", List.of("be", "fe"), "720h0m0s");
        effector = new VeleroBackupEffector(() -> client, factory, sets);

        // Explicit chain (no deep stubs) so each level is a stable, verifiable reference:
        // client.genericKubernetesResources(rdc).inNamespace("velero").resource(cr).serverSideApply()
        when(client.genericKubernetesResources(any(ResourceDefinitionContext.class)))
                .thenReturn(mixedOp);
        when(mixedOp.inNamespace(eq("velero"))).thenReturn(nsOp);
        when(nsOp.resource(any(GenericKubernetesResource.class))).thenReturn(resourceOp);
        when(resourceOp.serverSideApply()).thenReturn(null);

        when(sets.markStatus(anyString(), anyString(), any())).thenReturn(Mono.just(1L));
    }

    private static BackupSet set(BackupCloudScope scope, String domain, List<String> services) {
        return new BackupSet("set-1", "domain-" + domain, 2L, scope, domain, "alice",
                services, BackupDestinationKind.OBJECT_STORE, "s3://bk-" + domain, null, null,
                BackupSet.STATUS_PENDING, Instant.now(), null, null);
    }

    @SuppressWarnings("unchecked")
    private GenericKubernetesResource captureAppliedCr() {
        ArgumentCaptor<GenericKubernetesResource> cap =
                ArgumentCaptor.forClass(GenericKubernetesResource.class);
        verify(nsOp).resource(cap.capture());
        return cap.getValue();
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> spec(GenericKubernetesResource cr) {
        return (Map<String, Object>) cr.getAdditionalProperties().get("spec");
    }

    // ── startBackup applies the brand-walled Backup CR + marks RUNNING ───────────────────

    @Test
    void startBackup_appliesBrandWalledBackupCr_andMarksRunning() {
        StepVerifier.create(effector.startBackup(set(BackupCloudScope.DOMAIN, "brandx",
                        List.of("postgres", "pvc"))))
                .verifyComplete();

        GenericKubernetesResource applied = captureAppliedCr();
        assertThat(applied.getKind()).isEqualTo("Backup");
        assertThat(applied.getApiVersion()).isEqualTo("velero.io/v1");
        // the applied CR carries the brand wall (defence-in-depth into the cluster).
        assertThat((List<String>) spec(applied).get("includedNamespaces"))
                .containsExactly("brandx-be", "brandx-fe");
        verify(resourceOp).serverSideApply();
        // set driven to RUNNING (Velero reconciles to terminal later).
        verify(sets).markStatus(eq("set-1"), eq(BackupSet.STATUS_RUNNING), any());
        verify(sets, never()).markStatus(eq("set-1"), eq(BackupSet.STATUS_FAILED), any());
    }

    @Test
    void startBackup_total_appliesCrossDomainBackupCr() {
        StepVerifier.create(effector.startBackup(set(BackupCloudScope.TOTAL, "default",
                        List.of("postgres"))))
                .verifyComplete();
        GenericKubernetesResource applied = captureAppliedCr();
        // TOTAL: no namespace wall.
        assertThat(spec(applied)).doesNotContainKey("includedNamespaces");
        verify(sets).markStatus(eq("set-1"), eq(BackupSet.STATUS_RUNNING), any());
    }

    // ── startBackup cluster rejection -> set FAILED, error swallowed ─────────────────────

    @Test
    void startBackup_clusterRejection_marksFailed_andCompletes() {
        when(resourceOp.serverSideApply())
                .thenThrow(new KubernetesClientException("forbidden: backups.velero.io is forbidden"));

        StepVerifier.create(effector.startBackup(set(BackupCloudScope.DOMAIN, "brandx",
                        List.of("postgres"))))
                .verifyComplete(); // swallowed: not a 500

        verify(sets).markStatus(eq("set-1"), eq(BackupSet.STATUS_FAILED), any());
        verify(sets, never()).markStatus(eq("set-1"), eq(BackupSet.STATUS_RUNNING), any());
    }

    // ── startRestore applies the Restore CR (referencing the backup) ─────────────────────

    @Test
    void startRestore_appliesRestoreCr_referencingBackup() {
        BackupSet s = set(BackupCloudScope.DOMAIN, "brandx", List.of("pvc"));
        StepVerifier.create(effector.startRestore(s)).verifyComplete();

        GenericKubernetesResource applied = captureAppliedCr();
        assertThat(applied.getKind()).isEqualTo("Restore");
        assertThat(spec(applied).get("backupName")).isEqualTo(factory.backupName(s));
        assertThat((List<String>) spec(applied).get("includedNamespaces"))
                .containsExactly("brandx-be", "brandx-fe");
        verify(resourceOp).serverSideApply();
    }

    @Test
    void startRestore_clusterRejection_marksFailed_andCompletes() {
        when(resourceOp.serverSideApply())
                .thenThrow(new KubernetesClientException("conflict"));
        StepVerifier.create(effector.startRestore(set(BackupCloudScope.DOMAIN, "brandx",
                        List.of("pvc"))))
                .verifyComplete();
        verify(sets).markStatus(eq("set-1"), eq(BackupSet.STATUS_FAILED), any());
    }
}
