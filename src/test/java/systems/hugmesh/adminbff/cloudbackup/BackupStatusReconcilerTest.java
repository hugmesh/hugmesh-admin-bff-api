package systems.hugmesh.adminbff.cloudbackup;

import org.junit.jupiter.api.Test;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;
import systems.hugmesh.adminbff.servicecatalog.PerServiceIdentity;
import systems.hugmesh.adminbff.lease.LeaderElection;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * The catalog-write status reconciler over a MOCKED {@link VeleroStatusReader} +
 * {@link BackupSetRepository} (NEVER a real cluster, NEVER a real DB) + a toggleable fake leader.
 * Pins the closed-loop contract:
 * <ul>
 *   <li>terminal {@code Completed}/{@code PartiallyFailed} CR -> set marked {@code complete} via the
 *       sole-writer {@code markStatus}; {@code Failed}/{@code FailedValidation} -> {@code failed};</li>
 *   <li>non-terminal CR ({@code InProgress}) -> set left {@code running}, NO write;</li>
 *   <li>already-terminal set -> NO write (idempotent — a second sweep is a no-op);</li>
 *   <li>unmappable CR (no annotation/label) or a CR mapping to no row -> skipped safely (no crash);</li>
 *   <li>not-leader -> the whole sweep is skipped (single-writer);</li>
 *   <li>the CR->set key: the raw-id ANNOTATION wins over the (lossless-for-UUID) label slug;</li>
 *   <li>error surfacing: the scheduled {@code runOnce()} SWALLOWS a cluster-read failure (returns
 *       {@code 0}, retry next tick) while the on-demand {@code sweepNow()} PROPAGATES it.</li>
 * </ul>
 */
class BackupStatusReconcilerTest {

    private final VeleroStatusReader reader = mock(VeleroStatusReader.class);
    private final BackupSetRepository sets = mock(BackupSetRepository.class);

    /** A leader gate we can flip (the GameInstanceReconcilerTest FakeLeader idiom). */
    static final class FakeLeader implements LeaderElection {
        boolean leader = true;
        @Override public boolean isLeader() { return leader; }
        @Override public String label() { return "fake(leader=" + leader + ")"; }
    }

    private final FakeLeader leader = new FakeLeader();
    private final BackupStatusReconciler reconciler =
            new BackupStatusReconciler(reader, sets, leader);

    // ── fixtures ─────────────────────────────────────────────────────────────────────────

    private static BackupSet runningSet(String id) {
        return new BackupSet(id, "nightly", 3L, BackupCloudScope.DOMAIN, "brand-a", "subj",
                List.of("postgres"), BackupDestinationKind.OBJECT_STORE, "s3://b", 4096L, null,
                BackupSet.STATUS_RUNNING, Instant.now(), Instant.now(), null);
    }

    private static BackupSet withStatus(String id, String status) {
        BackupSet s = runningSet(id);
        return new BackupSet(s.id(), s.setKey(), s.version(), s.scope(), s.domain(), s.createdBy(),
                s.services(), s.destinationKind(), s.destinationRef(), s.sizeBytes(),
                s.encryptionMeta(), status, s.createdAt(), s.startedAt(), s.completedAt());
    }

    /** A CR carrying ONLY the slug label (the effector's current stamp) — the fallback key path. */
    private static VeleroCr crByLabel(String kind, String phase, String setId) {
        return new VeleroCr(kind, "hugmesh-bk-nightly-v3", phase, null,
                PerServiceIdentity.slug(setId));
    }

    // ── terminal -> sole-writer write ──────────────────────────────────────────────────────

    @Test
    void completedCr_marksSetComplete_viaSoleWriter() {
        String id = UUID.randomUUID().toString();
        when(reader.listManagedBackupsAndRestores())
                .thenReturn(Flux.just(crByLabel("Backup", "Completed", id)));
        when(sets.findById(id)).thenReturn(Mono.just(runningSet(id)));
        when(sets.markStatus(eq(id), eq(BackupSet.STATUS_COMPLETE), any())).thenReturn(Mono.just(1L));

        StepVerifier.create(reconciler.runOnce()).expectNext(1L).verifyComplete();

        verify(sets).markStatus(eq(id), eq(BackupSet.STATUS_COMPLETE), eq(4096L));
    }

    @Test
    void failedCr_marksSetFailed_viaSoleWriter() {
        String id = UUID.randomUUID().toString();
        when(reader.listManagedBackupsAndRestores())
                .thenReturn(Flux.just(crByLabel("Backup", "Failed", id)));
        when(sets.findById(id)).thenReturn(Mono.just(runningSet(id)));
        when(sets.markStatus(eq(id), eq(BackupSet.STATUS_FAILED), any())).thenReturn(Mono.just(1L));

        StepVerifier.create(reconciler.runOnce()).expectNext(1L).verifyComplete();

        verify(sets).markStatus(eq(id), eq(BackupSet.STATUS_FAILED), any());
    }

    @Test
    void partiallyFailedCr_isTreatedAsComplete() {
        String id = UUID.randomUUID().toString();
        when(reader.listManagedBackupsAndRestores())
                .thenReturn(Flux.just(crByLabel("Backup", "PartiallyFailed", id)));
        when(sets.findById(id)).thenReturn(Mono.just(runningSet(id)));
        when(sets.markStatus(eq(id), eq(BackupSet.STATUS_COMPLETE), any())).thenReturn(Mono.just(1L));

        StepVerifier.create(reconciler.runOnce()).expectNext(1L).verifyComplete();

        verify(sets).markStatus(eq(id), eq(BackupSet.STATUS_COMPLETE), any());
    }

    @Test
    void restoreCr_failedValidation_marksFailed() {
        String id = UUID.randomUUID().toString();
        when(reader.listManagedBackupsAndRestores())
                .thenReturn(Flux.just(crByLabel("Restore", "FailedValidation", id)));
        when(sets.findById(id)).thenReturn(Mono.just(runningSet(id)));
        when(sets.markStatus(eq(id), eq(BackupSet.STATUS_FAILED), any())).thenReturn(Mono.just(1L));

        StepVerifier.create(reconciler.runOnce()).expectNext(1L).verifyComplete();

        verify(sets).markStatus(eq(id), eq(BackupSet.STATUS_FAILED), any());
    }

    // ── non-terminal -> NO write ───────────────────────────────────────────────────────────

    @Test
    void inProgressCr_leavesSetRunning_noWrite() {
        String id = UUID.randomUUID().toString();
        when(reader.listManagedBackupsAndRestores())
                .thenReturn(Flux.just(crByLabel("Backup", "InProgress", id)));

        StepVerifier.create(reconciler.runOnce()).expectNext(0L).verifyComplete();

        verify(sets, never()).findById(anyString());
        verify(sets, never()).markStatus(anyString(), anyString(), any());
    }

    @Test
    void noStatusYet_isNonTerminal_noWrite() {
        String id = UUID.randomUUID().toString();
        when(reader.listManagedBackupsAndRestores())
                .thenReturn(Flux.just(crByLabel("Backup", null, id)));

        StepVerifier.create(reconciler.runOnce()).expectNext(0L).verifyComplete();

        verify(sets, never()).markStatus(anyString(), anyString(), any());
    }

    // ── idempotency: already-terminal set -> NO write ──────────────────────────────────────

    @Test
    void alreadyCompleteSet_isSkipped_idempotent() {
        String id = UUID.randomUUID().toString();
        when(reader.listManagedBackupsAndRestores())
                .thenReturn(Flux.just(crByLabel("Backup", "Completed", id)));
        when(sets.findById(id)).thenReturn(Mono.just(withStatus(id, BackupSet.STATUS_COMPLETE)));

        StepVerifier.create(reconciler.runOnce()).expectNext(0L).verifyComplete();

        verify(sets, never()).markStatus(anyString(), anyString(), any());
    }

    @Test
    void alreadyFailedSet_isSkipped_idempotent() {
        String id = UUID.randomUUID().toString();
        when(reader.listManagedBackupsAndRestores())
                .thenReturn(Flux.just(crByLabel("Backup", "Completed", id)));
        when(sets.findById(id)).thenReturn(Mono.just(withStatus(id, BackupSet.STATUS_FAILED)));

        StepVerifier.create(reconciler.runOnce()).expectNext(0L).verifyComplete();

        verify(sets, never()).markStatus(anyString(), anyString(), any());
    }

    @Test
    void reconcilingTwice_secondPassIsNoOp() {
        String id = UUID.randomUUID().toString();
        when(reader.listManagedBackupsAndRestores())
                .thenReturn(Flux.just(crByLabel("Backup", "Completed", id)))
                .thenReturn(Flux.just(crByLabel("Backup", "Completed", id)));
        // First pass sees it running; the (simulated) write means the second pass sees it complete.
        when(sets.findById(id))
                .thenReturn(Mono.just(runningSet(id)))
                .thenReturn(Mono.just(withStatus(id, BackupSet.STATUS_COMPLETE)));
        when(sets.markStatus(eq(id), eq(BackupSet.STATUS_COMPLETE), any())).thenReturn(Mono.just(1L));

        StepVerifier.create(reconciler.runOnce()).expectNext(1L).verifyComplete();
        StepVerifier.create(reconciler.runOnce()).expectNext(0L).verifyComplete();

        // markStatus called exactly ONCE across both passes.
        verify(sets).markStatus(eq(id), eq(BackupSet.STATUS_COMPLETE), any());
    }

    // ── unmappable / missing row -> skipped safely ─────────────────────────────────────────

    @Test
    void unmappableCr_noAnnotationOrLabel_isSkipped_noCrash() {
        when(reader.listManagedBackupsAndRestores())
                .thenReturn(Flux.just(new VeleroCr("Backup", "orphan-bk", "Completed", null, null)));

        StepVerifier.create(reconciler.runOnce()).expectNext(0L).verifyComplete();

        verify(sets, never()).findById(anyString());
        verify(sets, never()).markStatus(anyString(), anyString(), any());
    }

    @Test
    void crMappingToNoRow_isSkipped_noCrash() {
        String id = UUID.randomUUID().toString();
        when(reader.listManagedBackupsAndRestores())
                .thenReturn(Flux.just(crByLabel("Backup", "Completed", id)));
        when(sets.findById(id)).thenReturn(Mono.empty()); // no such row

        StepVerifier.create(reconciler.runOnce()).expectNext(0L).verifyComplete();

        verify(sets, never()).markStatus(anyString(), anyString(), any());
    }

    // ── single-writer: not leader -> whole sweep skipped ───────────────────────────────────

    @Test
    void notLeader_skipsEntireSweep() {
        leader.leader = false;

        StepVerifier.create(reconciler.runOnce()).expectNext(0L).verifyComplete();

        verify(reader, never()).listManagedBackupsAndRestores();
        verify(sets, never()).markStatus(anyString(), anyString(), any());
    }

    // ── CR->set mapping: annotation (raw id) wins over label (slug) ────────────────────────

    @Test
    void mapping_annotationRawIdWins_overLabelSlug() {
        String rawId = UUID.randomUUID().toString();
        // annotation carries the raw id; label carries a DIFFERENT (stale) slug.
        VeleroCr cr = new VeleroCr("Backup", "hugmesh-bk-nightly-v3", "Completed", rawId,
                "some-other-slug");
        when(reader.listManagedBackupsAndRestores()).thenReturn(Flux.just(cr));
        when(sets.findById(rawId)).thenReturn(Mono.just(runningSet(rawId)));
        when(sets.markStatus(eq(rawId), eq(BackupSet.STATUS_COMPLETE), any()))
                .thenReturn(Mono.just(1L));

        StepVerifier.create(reconciler.runOnce()).expectNext(1L).verifyComplete();

        // resolved by the RAW-id annotation, never the stale label slug.
        verify(sets).findById(rawId);
        verify(sets, never()).findById("some-other-slug");
    }

    // ── error surfacing: scheduled swallows, manual propagates ─────────────────────────────

    @Test
    void runOnce_swallowsClusterReadFailure_returnsZero_forScheduledRetry() {
        when(reader.listManagedBackupsAndRestores())
                .thenReturn(Flux.error(new IllegalStateException("cluster unreachable")));

        // The scheduled loop must NEVER die on a tick failure — it logs and returns 0 to retry.
        StepVerifier.create(reconciler.runOnce()).expectNext(0L).verifyComplete();

        verify(sets, never()).markStatus(anyString(), anyString(), any());
    }

    @Test
    void sweepNow_propagatesClusterReadFailure_forManualTrigger() {
        IllegalStateException boom = new IllegalStateException("cluster unreachable");
        when(reader.listManagedBackupsAndRestores()).thenReturn(Flux.error(boom));

        // The on-demand path surfaces the failure so the controller can return 503.
        StepVerifier.create(reconciler.sweepNow())
                .expectErrorMatches(e -> e == boom)
                .verify();

        verify(sets, never()).markStatus(anyString(), anyString(), any());
    }

    @Test
    void sweepNow_notLeader_skipsAndReturnsZero_doesNotError() {
        leader.leader = false;

        // Not-leader is "nothing to do", not a failure — sweepNow returns 0 cleanly (no error).
        StepVerifier.create(reconciler.sweepNow()).expectNext(0L).verifyComplete();

        verify(reader, never()).listManagedBackupsAndRestores();
    }

    @Test
    void uuidSetId_roundTripsThroughSlug_losslessly_soLabelMappingIsReliable() {
        // The mapping's reliability rests on slug(uuid) == uuid. Pin it.
        for (int i = 0; i < 200; i++) {
            String uuid = UUID.randomUUID().toString();
            assertThat(PerServiceIdentity.slug(uuid)).isEqualTo(uuid);
        }
    }
}
