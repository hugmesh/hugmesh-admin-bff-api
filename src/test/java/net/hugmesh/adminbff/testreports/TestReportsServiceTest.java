package net.hugmesh.adminbff.testreports;

import org.junit.jupiter.api.Test;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;
import net.hugmesh.commons.web.ApiException;
import net.hugmesh.adminbff.web.dto.TestRunIngestRequest;

import java.time.Instant;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Service-layer rules: tier normalisation + validation (closed LEAN|HEAVY), the
 * QUEUED-insert → launch trigger flow, and the NOT_FOUND mapping for detail /
 * download / ingest of a missing run (so a bad id is a clean 404, never a 500).
 */
class TestReportsServiceTest {

    private final TestRunRepository repo = mock(TestRunRepository.class);
    private final TestRunOrchestrator orchestrator = mock(TestRunOrchestrator.class);
    private final TestReportArchive archive = mock(TestReportArchive.class);
    private final TestReportsService service =
            new TestReportsService(repo, orchestrator, archive, "build-commit-sha");

    private static TestRun run(String id, String tier, String status) {
        return new TestRun(id, Instant.now(), "admin@x", tier, TestRun.SOURCE_ADMIN, status,
                null, null, null, null, 0, 0, 0, 0, null, "lean/run-1/", null);
    }

    @Test
    void triggerRun_normalisesTier_insertsQueued_andLaunches() {
        TestRun queued = run("new-1", "LEAN", "QUEUED");
        when(repo.insert(eq("admin@x"), eq("LEAN"), eq(TestRun.SOURCE_ADMIN), eq("build-commit-sha")))
                .thenReturn(Mono.just(queued));
        when(orchestrator.launch(queued)).thenReturn(Mono.empty());

        StepVerifier.create(service.triggerRun("admin@x", "lean", null))
                .expectNext("new-1").verifyComplete();
        verify(orchestrator).launch(queued);
    }

    @Test
    void triggerRun_explicitCommitWins() {
        when(repo.insert(anyString(), eq("HEAVY"), anyString(), eq("pinnedsha")))
                .thenReturn(Mono.just(run("new-2", "HEAVY", "QUEUED")));
        when(orchestrator.launch(any())).thenReturn(Mono.empty());
        StepVerifier.create(service.triggerRun("admin@x", "HEAVY", "pinnedsha"))
                .expectNext("new-2").verifyComplete();
    }

    @Test
    void triggerRun_badTier_400_andNoInsert() {
        StepVerifier.create(service.triggerRun("admin@x", "TURBO", null))
                .expectErrorSatisfies(e -> assertThat(((ApiException) e).status().value()).isEqualTo(400))
                .verify();
        verify(repo, never()).insert(anyString(), anyString(), anyString(), any());
    }

    @Test
    void detail_missingRun_404() {
        when(repo.find("ghost")).thenReturn(Mono.empty());
        StepVerifier.create(service.detail("ghost"))
                .expectErrorSatisfies(e -> assertThat(((ApiException) e).status().value()).isEqualTo(404))
                .verify();
    }

    @Test
    void detail_returnsRunAndMatrix() {
        TestRun r = run("r1", "LEAN", "COMPLETED");
        TestRunResult res = new TestRunResult("x", "r1", "s", "ALL", "passed", 1, 0, 0, 1L, Instant.now());
        when(repo.find("r1")).thenReturn(Mono.just(r));
        when(repo.resultsFor("r1")).thenReturn(Flux.just(res));
        StepVerifier.create(service.detail("r1"))
                .assertNext(d -> {
                    assertThat(d.run().id()).isEqualTo("r1");
                    assertThat(d.results()).containsExactly(res);
                })
                .verifyComplete();
    }

    @Test
    void download_missingRun_404_andArchiveNeverTouched() {
        when(repo.find("ghost")).thenReturn(Mono.empty());
        StepVerifier.create(service.download("ghost"))
                .expectErrorSatisfies(e -> assertThat(((ApiException) e).status().value()).isEqualTo(404))
                .verify();
        verify(archive, never()).download(any());
    }

    @Test
    void download_existingRun_streamsFromArchiveReportRef() {
        when(repo.find("r1")).thenReturn(Mono.just(run("r1", "LEAN", "COMPLETED")));
        when(archive.download("lean/run-1/")).thenReturn(Flux.empty());
        StepVerifier.create(service.download("r1")).verifyComplete();
        verify(archive).download("lean/run-1/");
    }

    @Test
    void ingest_missingRun_404() {
        when(repo.find("ghost")).thenReturn(Mono.empty());
        var req = new TestRunIngestRequest("RUN", null, null, "passed", 1, 0, 0, 100, 1L, "x");
        StepVerifier.create(service.ingest("ghost", req))
                .expectErrorSatisfies(e -> assertThat(((ApiException) e).status().value()).isEqualTo(404))
                .verify();
        verify(orchestrator, never()).ingest(anyString(), any());
    }

    @Test
    void launchIsReal_delegatesToOrchestrator() {
        when(orchestrator.launchIsReal()).thenReturn(true);
        assertThat(service.launchIsReal()).isTrue();
    }

    @Test
    void history_listsRuns() {
        when(repo.list()).thenReturn(Flux.just(run("r1", "LEAN", "COMPLETED")));
        StepVerifier.create(service.history()).expectNextCount(1).verifyComplete();
    }
}
