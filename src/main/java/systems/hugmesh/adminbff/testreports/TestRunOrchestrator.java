package systems.hugmesh.adminbff.testreports;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.ClassPathResource;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.core.publisher.Sinks;
import reactor.core.scheduler.Schedulers;
import systems.hugmesh.adminbff.web.dto.TestRunIngestRequest;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Orchestrates a test-architecture run: render the test-runner Job manifest, apply
 * it for REAL via the {@link JobLauncher} (fabric8 when
 * {@code testreports.launch.enabled=true}, no-op otherwise), hold the per-run SSE
 * event bus, and ingest the per-(suite,role) events the runner POSTs back —
 * persisting them to {@code test_run_result} AND fanning them to live subscribers,
 * then closing out the {@code test_run} row terminally.
 *
 * <p>This is the design's "build the real applyJob k8s-client call + a real
 * event-ingest path" — distinct from the backup orchestrator, which only emits a
 * synthetic phase progression and never ingests anything real. The SSE bus reuses
 * the backup {@code Sinks.many().replay()} shape but the replay buffer is BOUNDED
 * ({@code testreports.sse.replay-buffer}, default 256 events) so a long heavy run
 * cannot grow the per-pod buffer without limit; the durable per-(suite,role) matrix
 * lives in {@code test_run_result} so a reconnecting admin (or a different replica /
 * a restarted pod) still sees full state from the DB.
 */
@Component
public class TestRunOrchestrator {

    private static final Logger log = LoggerFactory.getLogger(TestRunOrchestrator.class);

    private final TestRunRepository repo;
    private final JobLauncher launcher;
    private final int replayBuffer;

    /** Per-run hot event bus. Replay(N) so a late SSE subscriber still sees the last
     *  N events (a run may have started before the admin-ui connected). */
    private final Map<String, Sinks.Many<TestRunEvent>> sinks = new ConcurrentHashMap<>();

    public TestRunOrchestrator(
            TestRunRepository repo,
            JobLauncher launcher,
            @Value("${testreports.sse.replay-buffer:256}") int replayBuffer) {
        this.repo = repo;
        this.launcher = launcher;
        this.replayBuffer = Math.max(1, replayBuffer);
    }

    /** True when the launcher actually applies Jobs to a cluster (B4 seam signal). */
    public boolean launchIsReal() {
        return launcher.isReal();
    }

    /**
     * Launch the test-runner for an already-persisted QUEUED {@link TestRun}. Renders
     * + applies the Job, records the Job name + RUNNING status, and registers the SSE
     * sink. Returns when the launch is submitted; progress arrives via {@link #ingest}.
     */
    public Mono<Void> launch(TestRun run) {
        sinks.computeIfAbsent(run.id(),
                k -> Sinks.many().replay().limit(replayBuffer));
        return Mono.fromCallable(() -> {
                    String manifest = renderManifest(run);
                    return launcher.apply(manifest, run.id());
                })
                .subscribeOn(Schedulers.boundedElastic())
                .flatMap(jobName -> repo.markRunning(run.id(), jobName)
                        .doOnSuccess(v -> emit(run.id(), TestRunEvent.progress(run.id(), 0,
                                "test-runner Job '" + jobName + "' launched (tier=" + run.tier() + ")"))))
                .onErrorResume(e -> {
                    log.warn("[test-reports] launch of run {} failed: {}", run.id(), e.toString());
                    emit(run.id(), TestRunEvent.failed(run.id(), e.getMessage()));
                    completeSink(run.id());
                    return repo.updateStatus(run.id(), TestRun.STATUS_ERROR, e.getMessage());
                });
    }

    /**
     * Ingest one event the test-runner POSTed for {@code runId}: upsert the durable
     * per-(suite,role) row (SUITE) or close out the run terminally (RUN), and fan an
     * SSE event to live subscribers. Returns the freshly-updated {@link TestRun} so
     * the controller can echo the current roll-up.
     */
    public Mono<TestRun> ingest(String runId, TestRunIngestRequest in) {
        if (in.isRunLevel()) {
            return ingestRunLevel(runId, in);
        }
        return ingestSuite(runId, in);
    }

    private Mono<TestRun> ingestSuite(String runId, TestRunIngestRequest in) {
        String role = (in.role() == null || in.role().isBlank()) ? TestRunResult.ROLE_ALL : in.role();
        String state = mapState(in.state());
        return repo.upsertResult(runId, in.suite(), role, state,
                        in.passed(), in.failed(), in.skipped(), in.durationMs())
                .doOnSuccess(v -> emit(runId, TestRunEvent.suite(runId, in.suite(), role, state,
                        in.passed(), in.failed(), in.skipped(), in.percent(),
                        in.message() == null ? in.suite() + ": " + state : in.message())))
                .then(repo.find(runId));
    }

    private Mono<TestRun> ingestRunLevel(String runId, TestRunIngestRequest in) {
        String status = runStatusFor(in.state(), in.failed());
        // reportRef is preserved via COALESCE in repo.finish (pass null here) — the
        // runner records the bundle path separately via recordReportRef once flushed.
        return repo.finish(runId, status,
                        in.passed(), in.failed(), in.skipped(), in.durationMs(),
                        null, "error".equals(in.state()) ? in.message() : null)
                // Emit the terminal SSE event and complete the sink after persisting the run result.
                .doOnSuccess(v -> emitRunLevelEvent(runId, status, in))
                .then(repo.find(runId));
    }

    /** Emit the FAILED or COMPLETE terminal SSE event and complete the sink. */
    private void emitRunLevelEvent(String runId, String status, TestRunIngestRequest in) {
        if (TestRun.STATUS_ERROR.equals(status)) {
            emit(runId, TestRunEvent.failed(runId,
                    in.message() == null ? "run errored (inconclusive)" : in.message()));
        } else {
            emit(runId, TestRunEvent.complete(runId, in.passed(), in.failed(), in.skipped(),
                    in.message() == null
                            ? "run " + status.toLowerCase() + " ("
                              + in.passed() + " passed, " + in.failed() + " failed)"
                            : in.message()));
        }
        completeSink(runId);
    }

    /** Record the durable report-bundle path once the runner has flushed it to the PVC. */
    public Mono<Void> recordReportRef(String runId, String reportRef) {
        return repo.find(runId).flatMap(run -> repo.finish(runId, run.status(),
                run.passed(), run.failed(), run.skipped(), run.durationMs(), reportRef, run.error()));
    }

    /** The SSE stream for a run id. Unknown / reaped run → an empty completed stream
     *  (the admin-ui then falls back to the durable DB matrix), never a hang/error. */
    public Flux<TestRunEvent> events(String runId) {
        Sinks.Many<TestRunEvent> sink = sinks.get(runId);
        return sink == null ? Flux.empty() : sink.asFlux();
    }

    // ── manifest templating (BackupOrchestrator.renderManifest style) ────────

    String renderManifest(TestRun run) {
        String template;
        try {
            byte[] bytes = new ClassPathResource("jobs/test-runner-job.yaml").getInputStream().readAllBytes();
            template = new String(bytes, StandardCharsets.UTF_8);
        } catch (IOException e) {
            throw new IllegalStateException("test-runner job template missing: jobs/test-runner-job.yaml", e);
        }
        return template
                .replace("${RUN_ID}", run.id())
                .replace("${TIER}", run.tier())
                .replace("${COMMIT_SHA}", run.commitSha() == null ? "" : run.commitSha())
                .replace("${TRIGGER_SOURCE}", run.triggerSource());
    }

    // ── helpers ──────────────────────────────────────────────────────────────

    private void emit(String runId, TestRunEvent ev) {
        Sinks.Many<TestRunEvent> sink = sinks.get(runId);
        if (sink != null) sink.tryEmitNext(ev);
    }

    private void completeSink(String runId) {
        Sinks.Many<TestRunEvent> sink = sinks.get(runId);
        if (sink != null) sink.tryEmitComplete();
    }

    /** Map an ingest state to the per-(suite,role) result state vocabulary. */
    private static String mapState(String ingestState) {
        return switch (ingestState) {
            case "passed" -> TestRunResult.STATE_PASSED;
            case "failed", "error" -> TestRunResult.STATE_FAILED;
            case "skipped" -> TestRunResult.STATE_SKIPPED;
            default -> TestRunResult.STATE_RUNNING;
        };
    }

    /** Map the run-level terminal state to the test_run status vocabulary. ERROR is
     *  reserved for an inconclusive harness/peer failure (distinct from a real
     *  assertion FAILED). */
    private static String runStatusFor(String state, int failed) {
        if ("error".equals(state)) return TestRun.STATUS_ERROR;
        if ("failed".equals(state) || failed > 0) return TestRun.STATUS_FAILED;
        return TestRun.STATUS_COMPLETED;
    }
}
