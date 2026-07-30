package systems.hugmesh.adminbff.testreports;

import org.springframework.stereotype.Repository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.time.LocalDateTime;

/**
 * Reactive (R2DBC) store for {@code test_run} + {@code test_run_result} (Liquibase
 * changeset 070).
 *
 * <p>Backed by the Spring Data {@link TestRunRowRepository} + {@link
 * TestRunResultRowRepository} (no raw {@code DatabaseClient}); maps the row entities to
 * the {@link TestRun} / {@link TestRunResult} JSON projections. The per-(suite,role)
 * roll-up is a portable find-then-update|insert upsert; the state transitions use the
 * COALESCE / state-guarded / CASE @Query constants so behaviour is preserved.
 */
@Repository
public class TestRunRepository {

    private final TestRunRowRepository runs;
    private final TestRunResultRowRepository results;

    public TestRunRepository(TestRunRowRepository runs, TestRunResultRowRepository results) {
        this.runs = runs;
        this.results = results;
    }

    // ── test_run ────────────────────────────────────────────────────────────

    /** Newest-first run history for the admin Test-Reports table. */
    public Flux<TestRun> list() {
        return runs.findAllByOrderByCreatedAtDesc().map(TestRunRow::toDomain);
    }

    public Mono<TestRun> find(String id) {
        return runs.findById(id).map(TestRunRow::toDomain);
    }

    /** Insert a freshly-queued run row (DB-generated id) and return it. The INSERT omits
     *  {@code id} (filled from the {@code (gen_random_uuid())::text} column DEFAULT, changelog
     *  200) and {@code RETURNING id} hands back the generated string, which we read back by
     *  that id to return the persisted row (same field order/values as before; the lifecycle
     *  columns are NULL and the four counters 0). */
    public Mono<TestRun> insert(String triggeredBy, String tier, String triggerSource, String commitSha) {
        return runs.insertReturningId(LocalDateTime.now(), triggeredBy, tier, triggerSource,
                        "QUEUED", commitSha, 0, 0, 0, 0)
                .flatMap(genId -> runs.findById(genId).map(TestRunRow::toDomain));
    }

    /** Mark a run RUNNING + record the launched k8s Job name + the start clock. */
    public Mono<Void> markRunning(String id, String jobName) {
        return runs.markRunning(id, jobName).then();
    }

    /** Close out a run terminally with the final roll-up counters + the stored report path. */
    public Mono<Void> finish(String id, String status, int passed, int failed, int skipped,
                             Long durationMs, String reportRef, String error) {
        return runs.finish(id, status, passed + failed + skipped, passed, failed, skipped,
                durationMs, reportRef, error).then();
    }

    /** Generic status move (used by the orchestrator's error paths). */
    public Mono<Void> updateStatus(String id, String status, String error) {
        return runs.updateStatus(id, status, error).then();
    }

    // ── test_run_result (per-(suite,role) upsert) ────────────────────────────

    /** The per-(suite,role) matrix for a run, ordered for a stable UI render. */
    public Flux<TestRunResult> resultsFor(String runId) {
        return results.findByRunIdOrderBySuiteAscRoleAsc(runId).map(TestRunResultRow::toDomain);
    }

    /** Upsert one per-(suite,role) roll-up row (unique on run+suite+role). */
    public Mono<Void> upsertResult(String runId, String suite, String role, String state,
                                   int passed, int failed, int skipped, Long durationMs) {
        String r = (role == null || role.isBlank()) ? TestRunResult.ROLE_ALL : role;
        return results.findByRunIdAndSuiteAndRole(runId, suite, r)
                .flatMap(existing -> results.updateResult(
                        existing.id(), state, passed, failed, skipped, durationMs))
                // No existing (run,suite,role) row → INSERT a new one with a DB-generated id
                // (id OMITTED → (gen_random_uuid())::text DEFAULT, changelog 200; RETURNING id
                // reads it back). thenReturn(1L) keeps the 1-row-affected signal as before.
                .switchIfEmpty(Mono.defer(() -> results.insertReturningId(
                                runId, suite, r, state, passed, failed, skipped, durationMs,
                                LocalDateTime.now())
                        .thenReturn(1L)))
                .then();
    }

    /** Delete a run (cascades its result rows via the 070 FK) — retention prune. */
    public Mono<Void> delete(String id) {
        return runs.deleteById(id);
    }
}
