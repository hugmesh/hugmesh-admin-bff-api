package net.hugmesh.adminbff.testreports;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.core.io.buffer.DataBuffer;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import net.hugmesh.commons.web.ApiException;
import net.hugmesh.adminbff.web.dto.TestRunIngestRequest;

import java.util.List;

/**
 * Test-Reports application service (reactive). Owns the rules the controller must not
 * duplicate:
 * <ul>
 *   <li>tier normalisation/validation (closed {@code LEAN|HEAVY} vocabulary, DB-CHECK
 *       parity);</li>
 *   <li>creating the durable QUEUED {@code test_run} row then handing the run to the
 *       {@link TestRunOrchestrator} which renders + applies the REAL k8s Job and
 *       streams progress;</li>
 *   <li>resolving a run + its per-(suite,role) matrix for the detail view;</li>
 *   <li>streaming the stored artifact bundle (re-scrubbed) for download;</li>
 *   <li>routing ingest events from the test-runner into the orchestrator.</li>
 * </ul>
 */
@Service
public class TestReportsService {

    private final TestRunRepository repo;
    private final TestRunOrchestrator orchestrator;
    private final TestReportArchive archive;
    private final String buildCommit;

    public TestReportsService(TestRunRepository repo, TestRunOrchestrator orchestrator,
                              TestReportArchive archive,
                              @Value("${testreports.runner.commit:}") String buildCommit) {
        this.repo = repo;
        this.orchestrator = orchestrator;
        this.archive = archive;
        this.buildCommit = buildCommit;
    }

    /** Newest-first run history for the admin Test-Reports table. */
    public Flux<TestRun> history() {
        return repo.list();
    }

    /** A single run's summary + its per-(suite,role) matrix (the detail view). */
    public Mono<TestRunDetail> detail(String runId) {
        return repo.find(runId)
                .switchIfEmpty(Mono.error(new ApiException(HttpStatus.NOT_FOUND,
                        "test run '" + runId + "' not found")))
                .flatMap(run -> repo.resultsFor(runId).collectList()
                        .map(results -> new TestRunDetail(run, results)));
    }

    /**
     * Trigger a run on-demand. Validates tier, creates the QUEUED row, and launches
     * the real test-runner Job. Returns the new run id (progress streams on
     * {@link #events}).
     */
    public Mono<String> triggerRun(String triggeredBy, String tier, String commitSha) {
        final String normalisedTier;
        try {
            normalisedTier = normaliseTier(tier);
        } catch (IllegalArgumentException | ApiException e) {
            // a bad tier is a clean 400 on the Mono (never a synchronous throw that
            // would escape the reactive contract) — same shape as BackupService.
            return Mono.error(e instanceof ApiException a ? a : ApiException.badRequest(e.getMessage()));
        }
        final String commit = (commitSha == null || commitSha.isBlank()) ? buildCommitOrNull() : commitSha;
        return repo.insert(triggeredBy, normalisedTier, TestRun.SOURCE_ADMIN, commit)
                .flatMap(run -> orchestrator.launch(run).thenReturn(run.id()));
    }

    /** Stream the stored report bundle for a run as a re-scrubbed tar.gz. */
    public Flux<DataBuffer> download(String runId) {
        return repo.find(runId)
                .switchIfEmpty(Mono.error(new ApiException(HttpStatus.NOT_FOUND,
                        "test run '" + runId + "' not found")))
                .flatMapMany(run -> archive.download(run.reportRef()));
    }

    /** Ingest one event the test-runner POSTed (suite update or run-terminal). */
    public Mono<TestRun> ingest(String runId, TestRunIngestRequest in) {
        return repo.find(runId)
                .switchIfEmpty(Mono.error(new ApiException(HttpStatus.NOT_FOUND,
                        "test run '" + runId + "' not found")))
                .flatMap(run -> orchestrator.ingest(runId, in));
    }

    /** The live SSE event stream for a run. */
    public Flux<TestRunEvent> events(String runId) {
        return orchestrator.events(runId);
    }

    /** True when the launcher actually applies Jobs to a cluster (the B4 seam signal
     *  the prod-hygiene gate reads — exposed so the controller / actuator can report it). */
    public boolean launchIsReal() {
        return orchestrator.launchIsReal();
    }

    // ── helpers ──────────────────────────────────────────────────────────────

    private String buildCommitOrNull() {
        return (buildCommit == null || buildCommit.isBlank()) ? null : buildCommit;
    }

    private static String normaliseTier(String tier) {
        String t = tier == null ? TestRun.TIER_LEAN : tier.trim().toUpperCase();
        if (!TestRun.TIER_LEAN.equals(t) && !TestRun.TIER_HEAVY.equals(t)) {
            throw ApiException.badRequest("tier must be LEAN or HEAVY");
        }
        return t;
    }

    /** Run summary + its per-(suite,role) matrix (the {runId} detail payload). */
    public record TestRunDetail(TestRun run, List<TestRunResult> results) {
    }
}
