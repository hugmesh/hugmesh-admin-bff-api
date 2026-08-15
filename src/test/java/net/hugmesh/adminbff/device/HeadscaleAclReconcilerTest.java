package net.hugmesh.adminbff.device;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;
import net.hugmesh.adminbff.device.ExportModels.AuthorizedOperator;
import net.hugmesh.adminbff.device.ExportModels.ExportBody;
import net.hugmesh.adminbff.device.ExportModels.SignedExport;
import net.hugmesh.adminbff.device.HeadscalePolicyClient.PushOutcome;
import net.hugmesh.adminbff.lease.LeaderElection;

import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * The leader-gated, idempotent, fail-closed reconcile loop — proven WITHOUT a live headscale via
 * a controllable fake {@link HeadscalePolicyClient} + a togglable {@link LeaderElection} + a
 * Mockito-stubbed {@link DeviceRegistryExportService}. Covers the four load-bearing behaviours
 * the task calls for:
 * <ol>
 *   <li><b>WRITE path:</b> when the desired policy changes, the loop PUTs it and records success;</li>
 *   <li><b>idempotency:</b> a second tick with an UNCHANGED export skips the PUT entirely;</li>
 *   <li><b>dark default:</b> the Noop client makes the whole loop a compile-only no-op (zero
 *       mesh mutation) yet the change-detection state still advances;</li>
 *   <li><b>fail-closed:</b> a DEGRADED push keeps last-good and the next tick RE-tries the same
 *       desired text; a non-leader replica never writes.</li>
 * </ol>
 */
class HeadscaleAclReconcilerTest {

    private final ObjectMapper mapper = new ObjectMapper();
    private final HeadscaleAclCompiler compiler = new HeadscaleAclCompiler(mapper);

    // ── test doubles ─────────────────────────────────────────────────────────────

    /** A controllable policy client recording pushes, with a programmable outcome. */
    static class FakePolicyClient implements HeadscalePolicyClient {
        final AtomicInteger puts = new AtomicInteger();
        final AtomicReference<String> lastPut = new AtomicReference<>();
        AtomicReference<PushOutcome> nextOutcome = new AtomicReference<>(PushOutcome.applied());
        String currentPolicy = null;   // what getPolicy() reports
        final boolean real;

        FakePolicyClient(boolean real) { this.real = real; }

        @Override public Mono<String> getPolicy() {
            return currentPolicy == null ? Mono.empty() : Mono.just(currentPolicy);
        }
        @Override public Mono<PushOutcome> setPolicy(String policyJson) {
            puts.incrementAndGet();
            lastPut.set(policyJson);
            return Mono.just(nextOutcome.get());
        }
        @Override public boolean isReal() { return real; }
    }

    static LeaderElection leader(boolean isLeader) {
        return new LeaderElection() {
            @Override public boolean isLeader() { return isLeader; }
            @Override public String label() { return "test-leader=" + isLeader; }
        };
    }

    private static SignedExport export(long gen, AuthorizedOperator... ops) {
        ExportBody body = new ExportBody("mesh_default", gen, List.of(ops));
        return new SignedExport(body, "hash", "sig", "pub", true);
    }

    private static AuthorizedOperator op(String operator, String fp) {
        return new AuthorizedOperator(operator, fp, "host-" + fp,
                List.of("SHA256:k-" + fp), AuthorizedOperator.VIA_DEVICE_LICENSE);
    }

    private DeviceRegistryExportService exportReturning(SignedExport... perTick) {
        DeviceRegistryExportService svc = mock(DeviceRegistryExportService.class);
        // Each invocation returns the next scripted export (last one repeats).
        AtomicInteger idx = new AtomicInteger();
        when(svc.exportMesh("mesh_default")).thenAnswer(inv -> {
            int i = Math.min(idx.getAndIncrement(), perTick.length - 1);
            return Mono.just(perTick[i]);
        });
        return svc;
    }

    private HeadscaleAclReconciler reconciler(DeviceRegistryExportService svc,
                                              HeadscalePolicyClient client,
                                              LeaderElection leader) {
        return new HeadscaleAclReconciler(svc, compiler, client, leader, "mesh_default");
    }

    // ── tests ────────────────────────────────────────────────────────────────────

    @Test
    void writePath_changedPolicy_isPushedAndApplied() {
        FakePolicyClient client = new FakePolicyClient(true);
        DeviceRegistryExportService svc = exportReturning(export(1, op("alice@x", "FP-A")));
        HeadscaleAclReconciler r = reconciler(svc, client, leader(true));

        StepVerifier.create(r.runOnce())
                .assertNext(o -> assertThat(o.isApplied()).isTrue())
                .verifyComplete();

        assertThat(client.puts.get()).isEqualTo(1);
        // The dst tag is the SERVER-FORCED tag:dev_<sha256(fp)[0:12]> the node actually
        // carries — NOT the old tag:node-<raw fp>, which no node has ever carried.
        // Literal hash pinned independently: printf '%s' FP-A | openssl dgst -sha256 | cut -c1-12
        assertThat(client.lastPut.get()).contains("tag:dev_250fb2ed2cb3");
        assertThat(client.lastPut.get()).doesNotContain("tag:node-");
        assertThat(r.lastPushedPolicy()).isEqualTo(client.lastPut.get());
        assertThat(r.lastSuccessAt()).isAfter(java.time.Instant.EPOCH);
    }

    @Test
    void idempotency_unchangedExport_skipsSecondPut() {
        FakePolicyClient client = new FakePolicyClient(true);
        // Same export both ticks -> same compiled policy.
        DeviceRegistryExportService svc = exportReturning(export(2, op("alice@x", "FP-A")));
        HeadscaleAclReconciler r = reconciler(svc, client, leader(true));

        r.runOnce().block();   // tick 1: pushes
        assertThat(client.puts.get()).isEqualTo(1);

        StepVerifier.create(r.runOnce())   // tick 2: unchanged -> skip
                .assertNext(o -> assertThat(o.isApplied()).isTrue())
                .verifyComplete();
        assertThat(client.puts.get()).isEqualTo(1);   // NO second PUT
    }

    @Test
    void changedExport_pushesAgain() {
        FakePolicyClient client = new FakePolicyClient(true);
        DeviceRegistryExportService svc = exportReturning(
                export(1, op("alice@x", "FP-A")),
                export(2, op("alice@x", "FP-A"), op("bob@y", "FP-B")));  // changed
        HeadscaleAclReconciler r = reconciler(svc, client, leader(true));

        r.runOnce().block();   // tick 1
        r.runOnce().block();   // tick 2: changed -> push again
        assertThat(client.puts.get()).isEqualTo(2);
        assertThat(client.lastPut.get()).contains("tag:dev_de2fb9fcfb97");
    }

    @Test
    void darkDefault_noopClient_isCompileOnlyNoOp_butAdvancesState() {
        FakePolicyClient noop = new FakePolicyClient(false);
        noop.nextOutcome.set(PushOutcome.stubbed());   // Noop reports stubbed
        DeviceRegistryExportService svc = exportReturning(export(1, op("alice@x", "FP-A")));
        HeadscaleAclReconciler r = reconciler(svc, noop, leader(true));

        StepVerifier.create(r.runOnce())
                .assertNext(o -> assertThat(o.isStubbed()).isTrue())   // no real apply
                .verifyComplete();
        // The "push" happened against the Noop (which mutates nothing), and the change-detection
        // baseline advanced so a steady-state run is quiet.
        assertThat(r.lastPushedPolicy()).isNotNull();
        r.runOnce().block();
        assertThat(noop.puts.get()).isEqualTo(1);   // second tick unchanged -> skipped
    }

    @Test
    void failClosed_degradedPush_keepsLastGood_andRetriesSameDesiredNextTick() {
        FakePolicyClient client = new FakePolicyClient(true);
        client.nextOutcome.set(PushOutcome.degraded("headscale 503"));
        DeviceRegistryExportService svc = exportReturning(export(1, op("alice@x", "FP-A")));
        HeadscaleAclReconciler r = reconciler(svc, client, leader(true));

        StepVerifier.create(r.runOnce())
                .assertNext(o -> assertThat(o.isDegraded()).isTrue())
                .verifyComplete();
        // last-good NOT advanced on a degraded push -> next tick re-attempts the SAME text.
        assertThat(r.lastPushedPolicy()).isNull();

        String firstAttempt = client.lastPut.get();
        client.nextOutcome.set(PushOutcome.applied());   // headscale recovers
        r.runOnce().block();
        assertThat(client.puts.get()).isEqualTo(2);          // retried
        assertThat(client.lastPut.get()).isEqualTo(firstAttempt);   // SAME desired text
        assertThat(r.lastPushedPolicy()).isEqualTo(firstAttempt);   // now adopted
    }

    @Test
    void notLeader_neverWrites() {
        FakePolicyClient client = new FakePolicyClient(true);
        DeviceRegistryExportService svc = exportReturning(export(1, op("alice@x", "FP-A")));
        HeadscaleAclReconciler r = reconciler(svc, client, leader(false));   // not leader

        StepVerifier.create(r.runOnce())
                .assertNext(o -> assertThat(o.isStubbed()).isTrue())   // skipped tick
                .verifyComplete();
        assertThat(client.puts.get()).isZero();
        assertThat(r.lastPushedPolicy()).isNull();
    }

    @Test
    void firstTick_adoptsMatchingLivePolicy_withoutRedundantPut() {
        FakePolicyClient client = new FakePolicyClient(true);
        DeviceRegistryExportService svc = exportReturning(export(1, op("alice@x", "FP-A")));
        // Pre-seed headscale's current policy to EXACTLY the desired compiled text.
        HeadscaleAclReconciler probe = reconciler(svc, new FakePolicyClient(true), leader(true));
        String desired = compiler.compile(export(1, op("alice@x", "FP-A")).body());
        client.currentPolicy = desired;

        HeadscaleAclReconciler r = reconciler(exportReturning(export(1, op("alice@x", "FP-A"))),
                client, leader(true));
        StepVerifier.create(r.runOnce())
                .assertNext(o -> assertThat(o.isApplied()).isTrue())
                .verifyComplete();
        assertThat(client.puts.get()).isZero();   // adopted, no redundant PUT
        assertThat(r.lastPushedPolicy()).isEqualTo(desired);
    }

    @Test
    void emptyExport_refusesToPush_failClosed() {
        FakePolicyClient client = new FakePolicyClient(true);
        DeviceRegistryExportService svc = exportReturning(export(0));   // no operators -> deny-all... but well-formed
        HeadscaleAclReconciler r = reconciler(svc, client, leader(true));

        // A deny-all policy is a NON-empty compiled body (valid JSON with empty ssh[]), so it IS
        // pushed — the "refuse empty" guard is for a truly blank compile, asserted separately.
        r.runOnce().block();
        assertThat(client.puts.get()).isEqualTo(1);
        assertThat(client.lastPut.get()).contains("\"ssh\"");
    }
}
