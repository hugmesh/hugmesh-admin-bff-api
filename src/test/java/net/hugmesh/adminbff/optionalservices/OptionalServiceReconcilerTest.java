package net.hugmesh.adminbff.optionalservices;

import org.junit.jupiter.api.Test;
import net.hugmesh.adminbff.lease.LeaderElection;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The Lease-gated single-writer optional-services reconciler over the real
 * {@link OptionalServiceRegistry} + a recording client + recording write seams + a
 * toggleable fake leader. Proves the NodeStorageReconciler-cloned contract WITHOUT a
 * cluster:
 * <ul>
 *   <li><b>not-leader skips entirely</b> (single-writer): no write, no status;</li>
 *   <li><b>derives the desired map over the CLOSED slug set</b>: enabled CRs -&gt; true,
 *       every other managed slug -&gt; false, all present;</li>
 *   <li><b>both write targets receive the SAME desired map</b> (single source of truth);</li>
 *   <li><b>status</b>: enabled+ok -&gt; installed/Enabled; disabled+ok -&gt; !installed/Disabled;
 *       a write failure -&gt; Degraded + installed false;</li>
 *   <li><b>idempotent</b>: a second run yields the same desired map;</li>
 *   <li><b>unknown-slug CR</b> is ignored (never actuated, no status).</li>
 * </ul>
 */
class OptionalServiceReconcilerTest {

    private static final OptionalServiceRegistry REGISTRY = new OptionalServiceRegistry();

    // ── fakes ────────────────────────────────────────────────────────────────────────
    static final class FakeLeader implements LeaderElection {
        boolean leader;
        FakeLeader(boolean leader) { this.leader = leader; }
        @Override public boolean isLeader() { return leader; }
        @Override public String label() { return "fake(leader=" + leader + ")"; }
    }

    static OptionalServiceCr cr(String slug, boolean enabled) {
        return new OptionalServiceCr(slug, "devops", slug, enabled, null, null, 1L, "100");
    }

    static final class RecordingClient implements OptionalServiceClient {
        final List<OptionalServiceCr> crs;
        final List<Map.Entry<String, OptionalServiceStatus>> statuses = new ArrayList<>();
        RecordingClient(List<OptionalServiceCr> crs) { this.crs = crs; }
        @Override public List<OptionalServiceCr> listDesired() { return crs; }
        @Override public boolean updateStatus(OptionalServiceCr c, OptionalServiceStatus s) {
            statuses.add(Map.entry(c.slug(), s)); return true;
        }
        @Override public OptionalServiceCr setEnabled(String slug, boolean enabled, String reason,
                                                      String requestedBy) {
            // The reconcile loop never writes a CR spec — only the superadmin surface does
            // (OptionalServiceAdminService). Throwing keeps that boundary honest: if a future
            // reconciler change starts writing spec, this test dies instead of quietly passing.
            throw new UnsupportedOperationException("the reconciler must not write CR specs");
        }
        @Override public boolean isReal() { return true; }
        OptionalServiceStatus statusOf(String slug) {
            return statuses.stream().filter(e -> e.getKey().equals(slug))
                    .map(Map.Entry::getValue).reduce((a, b) -> b).orElse(null);
        }
    }

    static final class RecordingPatcher implements OptionalServiceApplicationSetPatcher {
        final List<Map<String, Boolean>> applied = new ArrayList<>();
        boolean ok = true;
        @Override public boolean apply(Map<String, Boolean> desired) { applied.add(Map.copyOf(desired)); return ok; }
        @Override public boolean isReal() { return true; }
        Map<String, Boolean> last() { return applied.get(applied.size() - 1); }
    }

    static final class RecordingWriter implements InstalledServicesConfigMapWriter {
        final List<Map<String, Boolean>> mirrored = new ArrayList<>();
        boolean ok = true;
        @Override public boolean mirror(Map<String, Boolean> desired) { mirrored.add(Map.copyOf(desired)); return ok; }
        @Override public boolean isReal() { return true; }
        Map<String, Boolean> last() { return mirrored.get(mirrored.size() - 1); }
    }

    private OptionalServiceReconciler newReconciler(FakeLeader leader, RecordingClient client,
                                                    RecordingPatcher patcher, RecordingWriter writer) {
        return new OptionalServiceReconciler(client, patcher, writer, REGISTRY, leader);
    }

    // ── tests ──────────────────────────────────────────────────────────────────────
    @Test
    void notLeader_skipsEntirely_noWriteNoStatus() {
        RecordingClient client = new RecordingClient(List.of(cr("akkoma", true)));
        RecordingPatcher patcher = new RecordingPatcher();
        RecordingWriter writer = new RecordingWriter();

        newReconciler(new FakeLeader(false), client, patcher, writer).runOnce().block();

        assertThat(patcher.applied).isEmpty();
        assertThat(writer.mirrored).isEmpty();
        assertThat(client.statuses).isEmpty();
    }

    @Test
    void leader_derivesClosedDesiredMap_bothTargetsSame() {
        RecordingClient client = new RecordingClient(List.of(
                cr("akkoma", true), cr("tuwunel", true), cr("games", false)));
        RecordingPatcher patcher = new RecordingPatcher();
        RecordingWriter writer = new RecordingWriter();

        newReconciler(new FakeLeader(true), client, patcher, writer).runOnce().block();

        Map<String, Boolean> desired = patcher.last();
        // ALL managed slugs present (count pinned by OptionalServiceRegistryParityTest,
        // never restated as a literal here); only CR-enabled ones true.
        assertThat(desired.keySet()).containsExactlyInAnyOrderElementsOf(REGISTRY.slugs());
        assertThat(desired.get("akkoma")).isTrue();
        assertThat(desired.get("tuwunel")).isTrue();
        assertThat(desired.get("games")).isFalse();
        assertThat(desired.get("owncast")).isFalse();   // no CR -> false default
        assertThat(desired.get("edge-ai")).isFalse();
        // both write targets got the identical desired map.
        assertThat(writer.last()).isEqualTo(desired);
    }

    @Test
    void leader_statusReflectsEnabledDisabled_whenOk() {
        RecordingClient client = new RecordingClient(List.of(cr("akkoma", true), cr("games", false)));
        newReconciler(new FakeLeader(true), client, new RecordingPatcher(), new RecordingWriter())
                .runOnce().block();

        OptionalServiceStatus on = client.statusOf("akkoma");
        assertThat(on.installed()).isTrue();
        assertThat(on.phase()).isEqualTo(OptionalServiceStatus.PHASE_ENABLED);
        assertThat(on.applicationName()).isEqualTo("optional-akkoma");

        OptionalServiceStatus off = client.statusOf("games");
        assertThat(off.installed()).isFalse();
        assertThat(off.phase()).isEqualTo(OptionalServiceStatus.PHASE_DISABLED);
    }

    @Test
    void leader_writeFailure_marksDegraded_installedFalse() {
        RecordingClient client = new RecordingClient(List.of(cr("akkoma", true)));
        RecordingPatcher patcher = new RecordingPatcher();
        patcher.ok = false; // ApplicationSet write fails
        newReconciler(new FakeLeader(true), client, patcher, new RecordingWriter()).runOnce().block();

        OptionalServiceStatus st = client.statusOf("akkoma");
        assertThat(st.phase()).isEqualTo(OptionalServiceStatus.PHASE_DEGRADED);
        assertThat(st.installed()).isFalse(); // never claims an install on a failed write
        assertThat(st.conditions()).anySatisfy(c -> {
            assertThat(c.type()).isEqualTo(OptionalServiceStatus.Condition.TYPE_APPLICATIONSET_PATCHED);
            assertThat(c.status()).isEqualTo("False");
        });
    }

    @Test
    void idempotent_secondRunSameDesired() {
        RecordingClient client = new RecordingClient(List.of(cr("akkoma", true)));
        RecordingPatcher patcher = new RecordingPatcher();
        OptionalServiceReconciler r =
                newReconciler(new FakeLeader(true), client, patcher, new RecordingWriter());
        r.runOnce().block();
        r.runOnce().block();
        assertThat(patcher.applied).hasSize(2);
        assertThat(patcher.applied.get(0)).isEqualTo(patcher.applied.get(1));
    }

    @Test
    void unknownSlugCr_ignored_notActuated_noStatus() {
        RecordingClient client = new RecordingClient(List.of(cr("akkoma", true), cr("bogus", true)));
        RecordingPatcher patcher = new RecordingPatcher();
        newReconciler(new FakeLeader(true), client, patcher, new RecordingWriter()).runOnce().block();

        assertThat(patcher.last()).doesNotContainKey("bogus");
        assertThat(client.statusOf("bogus")).isNull();      // never actuated
        assertThat(client.statusOf("akkoma")).isNotNull();  // the known one still reconciled
    }
}
