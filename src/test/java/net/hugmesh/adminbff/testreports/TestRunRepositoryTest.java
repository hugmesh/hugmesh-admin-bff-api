package net.hugmesh.adminbff.testreports;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.data.r2dbc.test.autoconfigure.DataR2dbcTest;
import org.springframework.context.annotation.Import;
import net.hugmesh.adminbff.support.TestDatabaseConfig;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Validates the test_run + test_run_result R2DBC SQL against H2 (PostgreSQL-compat)
 * with the Liquibase-applied changeset 070: insert (QUEUED) → markRunning → finish
 * (terminal roll-up + report_ref), the per-(suite,role) upsert (insert then update
 * the SAME row, unique on run+suite+role), the FK cascade on delete, and that the
 * newest-first list + detail matrix round-trip.
 */
@DataR2dbcTest
@Import({TestDatabaseConfig.class, TestRunRepository.class})
class TestRunRepositoryTest {

    @Autowired TestRunRepository repo;

    @Test
    void insertRunningFinish_roundTrip() {
        TestRun run = repo.insert("admin@x", TestRun.TIER_LEAN, TestRun.SOURCE_ADMIN, "abc1234").block();
        assertThat(run.id()).isNotBlank();
        assertThat(run.status()).isEqualTo(TestRun.STATUS_QUEUED);
        assertThat(run.tier()).isEqualTo(TestRun.TIER_LEAN);
        assertThat(run.triggerSource()).isEqualTo(TestRun.SOURCE_ADMIN);
        assertThat(run.commitSha()).isEqualTo("abc1234");
        assertThat(run.createdAt()).isNotNull();

        repo.markRunning(run.id(), "hugmesh-test-runner-job-1").block();
        TestRun running = repo.find(run.id()).block();
        assertThat(running.status()).isEqualTo(TestRun.STATUS_RUNNING);
        assertThat(running.jobName()).isEqualTo("hugmesh-test-runner-job-1");
        assertThat(running.startedAt()).isNotNull();

        repo.finish(run.id(), TestRun.STATUS_COMPLETED, 40, 0, 2, 12345L,
                "lean/run-1-abc1234/", null).block();
        TestRun done = repo.find(run.id()).block();
        assertThat(done.status()).isEqualTo(TestRun.STATUS_COMPLETED);
        assertThat(done.passed()).isEqualTo(40);
        assertThat(done.failed()).isZero();
        assertThat(done.skipped()).isEqualTo(2);
        assertThat(done.totalTests()).isEqualTo(42);
        assertThat(done.durationMs()).isEqualTo(12345L);
        assertThat(done.reportRef()).isEqualTo("lean/run-1-abc1234/");
        assertThat(done.finishedAt()).isNotNull();
        assertThat(done.terminal()).isTrue();

        // newest-first list contains the run.
        assertThat(repo.list().collectList().block())
                .extracting(TestRun::id).contains(run.id());
    }

    @Test
    void markRunning_onlyFromQueued() {
        TestRun run = repo.insert("admin@x", TestRun.TIER_HEAVY, TestRun.SOURCE_HEAVY_ATTACH, null).block();
        repo.markRunning(run.id(), "job-a").block();
        // A second markRunning is a no-op (status already RUNNING) — the job name stays.
        repo.markRunning(run.id(), "job-b").block();
        assertThat(repo.find(run.id()).block().jobName()).isEqualTo("job-a");
    }

    @Test
    void upsertResult_insertsThenUpdatesSameRow() {
        TestRun run = repo.insert("admin@x", TestRun.TIER_LEAN, TestRun.SOURCE_ARGOCD, null).block();

        repo.upsertResult(run.id(), "19-local-only-mastodon", "e2e-mastodon-domainlocked",
                TestRunResult.STATE_RUNNING, 0, 0, 0, null).block();
        repo.upsertResult(run.id(), "19-local-only-mastodon", "e2e-mastodon-domainlocked",
                TestRunResult.STATE_PASSED, 3, 0, 0, 800L).block();
        // a different role on the same suite is a SEPARATE row.
        repo.upsertResult(run.id(), "19-local-only-mastodon", TestRunResult.ROLE_ALL,
                TestRunResult.STATE_PASSED, 1, 0, 0, 100L).block();

        List<TestRunResult> results = repo.resultsFor(run.id()).collectList().block();
        assertThat(results).hasSize(2);
        TestRunResult locked = results.stream()
                .filter(r -> "e2e-mastodon-domainlocked".equals(r.role())).findFirst().orElseThrow();
        assertThat(locked.state()).isEqualTo(TestRunResult.STATE_PASSED);
        assertThat(locked.passed()).isEqualTo(3);
        assertThat(locked.durationMs()).isEqualTo(800L);
    }

    @Test
    void nullRole_defaultsToAll() {
        TestRun run = repo.insert("admin@x", TestRun.TIER_LEAN, TestRun.SOURCE_ADMIN, null).block();
        repo.upsertResult(run.id(), "22-mrf-local-only-smoke", null,
                TestRunResult.STATE_PASSED, 1, 0, 0, 50L).block();
        TestRunResult only = repo.resultsFor(run.id()).blockFirst();
        assertThat(only.role()).isEqualTo(TestRunResult.ROLE_ALL);
    }

    @Test
    void delete_cascadesResultMatrix() {
        TestRun run = repo.insert("admin@x", TestRun.TIER_HEAVY, TestRun.SOURCE_ADMIN, null).block();
        repo.upsertResult(run.id(), "24-final-e2e-sweep", "e2e-admin",
                TestRunResult.STATE_PASSED, 5, 0, 0, 900L).block();
        assertThat(repo.resultsFor(run.id()).collectList().block()).hasSize(1);

        repo.delete(run.id()).block();
        assertThat(repo.find(run.id()).block()).isNull();
        // the FK ON DELETE CASCADE reaped the per-(suite,role) rows.
        assertThat(repo.resultsFor(run.id()).collectList().block()).isEmpty();
    }
}
