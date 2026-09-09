package net.hugmesh.adminbff.testreports;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.data.r2dbc.test.autoconfigure.DataR2dbcTest;
import org.springframework.context.annotation.Import;
import reactor.test.StepVerifier;
import net.hugmesh.adminbff.support.TestDatabaseConfig;
import net.hugmesh.adminbff.web.dto.TestRunIngestRequest;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import reactor.core.publisher.Mono;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * End-to-end-ish orchestrator behaviour against the REAL H2 repo (so the durable
 * test_run / test_run_result writes are genuinely exercised), with a fake
 * {@link JobLauncher} standing in for the cluster:
 * <ul>
 *   <li>launch → the run goes RUNNING + records the launched Job name + emits a
 *       launch SSE event;</li>
 *   <li>a SUITE ingest → upserts the per-(suite,role) row AND fans an SSE event;</li>
 *   <li>a RUN-terminal ingest → closes the run COMPLETED/FAILED + emits the terminal
 *       SSE event + completes the sink;</li>
 *   <li>a failing launcher → the run is ERRORed (inconclusive), not 500.</li>
 * </ul>
 */
@DataR2dbcTest
@Import({TestDatabaseConfig.class, TestRunRepository.class})
class TestRunOrchestratorTest {

    @Autowired TestRunRepository repo;

    /** Records every applied manifest so the template substitution is asserted. */
    static final class CapturingLauncher implements JobLauncher {
        final List<String> manifests = new ArrayList<>();
        private final boolean real;
        private final RuntimeException boom;
        CapturingLauncher(boolean real, RuntimeException boom) { this.real = real; this.boom = boom; }
        @Override public Mono<String> apply(String manifest, String runId) {
            return Mono.fromCallable(() -> {
                manifests.add(manifest);
                if (boom != null) throw boom;
                return "hugmesh-test-runner-" + runId;
            });
        }
        @Override public boolean isReal() { return real; }
    }

    private TestRunOrchestrator orchestrator(JobLauncher launcher) {
        return new TestRunOrchestrator(repo, launcher, 64);
    }

    @Test
    void launch_marksRunningAndRecordsJobName_andSubstitutesTemplate() {
        CapturingLauncher launcher = new CapturingLauncher(true, null);
        TestRunOrchestrator orch = orchestrator(launcher);
        assertThat(orch.launchIsReal()).isTrue();

        TestRun run = repo.insert("admin@x", TestRun.TIER_HEAVY, TestRun.SOURCE_ADMIN, "deadbee").block();
        orch.launch(run).block();

        TestRun after = repo.find(run.id()).block();
        assertThat(after.status()).isEqualTo(TestRun.STATUS_RUNNING);
        assertThat(after.jobName()).isEqualTo("hugmesh-test-runner-" + run.id());
        // the rendered manifest carries the substituted run id + tier (no leftover ${...}).
        assertThat(launcher.manifests).hasSize(1);
        String m = launcher.manifests.get(0);
        assertThat(m).contains(run.id()).contains("HEAVY").doesNotContain("${RUN_ID}").doesNotContain("${TIER}");
    }

    @Test
    void ingestSuite_upsertsMatrixAndFansSseEvent() {
        TestRunOrchestrator orch = orchestrator(new CapturingLauncher(false, null));
        TestRun run = repo.insert("admin@x", TestRun.TIER_LEAN, TestRun.SOURCE_ARGOCD, null).block();
        orch.launch(run).block();

        var suite = new TestRunIngestRequest("SUITE", "19-local-only-mastodon",
                "e2e-mastodon-domainlocked", "passed", 3, 0, 0, 50, 800L, "mastodon local-only ok");

        // subscribe to the live stream, then ingest — the event must arrive.
        StepVerifier.create(orch.events(run.id()).filter(e -> e.suite() != null).next())
                .then(() -> orch.ingest(run.id(), suite).block())
                .assertNext(ev -> {
                    assertThat(ev.suite()).isEqualTo("19-local-only-mastodon");
                    assertThat(ev.role()).isEqualTo("e2e-mastodon-domainlocked");
                    assertThat(ev.state()).isEqualTo("passed");
                    assertThat(ev.passed()).isEqualTo(3);
                })
                .verifyComplete();

        // and the durable matrix row was upserted.
        List<TestRunResult> results = repo.resultsFor(run.id()).collectList().block();
        assertThat(results).hasSize(1);
        assertThat(results.get(0).state()).isEqualTo(TestRunResult.STATE_PASSED);
    }

    @Test
    void ingestRunTerminal_closesRunAndCompletesSink() {
        TestRunOrchestrator orch = orchestrator(new CapturingLauncher(false, null));
        TestRun run = repo.insert("admin@x", TestRun.TIER_LEAN, TestRun.SOURCE_ADMIN, null).block();
        orch.launch(run).block();

        var terminal = new TestRunIngestRequest("RUN", null, null, "passed",
                40, 0, 2, 100, 12345L, "all green");
        orch.ingest(run.id(), terminal).block();

        TestRun done = repo.find(run.id()).block();
        assertThat(done.status()).isEqualTo(TestRun.STATUS_COMPLETED);
        assertThat(done.passed()).isEqualTo(40);
        assertThat(done.skipped()).isEqualTo(2);
        assertThat(done.terminal()).isTrue();

        // the sink is completed: the replay stream terminates (no hang).
        StepVerifier.create(orch.events(run.id()).collectList())
                .assertNext(events -> assertThat(events).anyMatch(TestRunEvent::done))
                .verifyComplete();
    }

    @Test
    void ingestRunTerminal_withFailures_marksFailed() {
        TestRunOrchestrator orch = orchestrator(new CapturingLauncher(false, null));
        TestRun run = repo.insert("admin@x", TestRun.TIER_HEAVY, TestRun.SOURCE_HEAVY_ATTACH, null).block();
        orch.launch(run).block();
        orch.ingest(run.id(), new TestRunIngestRequest("RUN", null, null, "failed",
                38, 2, 0, 100, 9000L, "2 failed")).block();
        assertThat(repo.find(run.id()).block().status()).isEqualTo(TestRun.STATUS_FAILED);
    }

    @Test
    void ingestRunTerminal_error_marksErrorInconclusive() {
        TestRunOrchestrator orch = orchestrator(new CapturingLauncher(false, null));
        TestRun run = repo.insert("admin@x", TestRun.TIER_LEAN, TestRun.SOURCE_ADMIN, null).block();
        orch.launch(run).block();
        orch.ingest(run.id(), new TestRunIngestRequest("RUN", null, null, "error",
                0, 0, 0, 100, null, "peer pairing broken — inconclusive")).block();
        TestRun errored = repo.find(run.id()).block();
        assertThat(errored.status()).isEqualTo(TestRun.STATUS_ERROR);
        assertThat(errored.error()).contains("peer pairing");
    }

    @Test
    void launch_launcherThrows_marksErrorNotCrash() {
        CapturingLauncher boom = new CapturingLauncher(true,
                new RuntimeException("cluster says no"));
        TestRunOrchestrator orch = orchestrator(boom);
        TestRun run = repo.insert("admin@x", TestRun.TIER_LEAN, TestRun.SOURCE_ADMIN, null).block();

        // launch returns normally (no error propagated) and the run is ERRORed.
        orch.launch(run).block(Duration.ofSeconds(5));
        TestRun after = repo.find(run.id()).block();
        assertThat(after.status()).isEqualTo(TestRun.STATUS_ERROR);
        assertThat(after.error()).contains("cluster says no");
    }
}
