package net.hugmesh.adminbff.testreports;

import org.springframework.data.r2dbc.repository.Modifying;
import org.springframework.data.r2dbc.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.time.LocalDateTime;

/**
 * Reactive (R2DBC) Spring Data store for {@code test_run} (changeset 070). The list is a
 * derived finder; the state-guarded RUNNING transition, the terminal finish roll-up, and
 * the generic CASE-bearing status move are {@code @Query} static-final constants (the
 * COALESCE keep-existing + state-guard + CASE finished_at are not derivable). The {@link
 * TestRunRepository} facade maps rows to/from {@link TestRun}.
 *
 * <p>DB-GENERATED PK (changelog 200): the varchar(36) {@code id} carries a
 * {@code (gen_random_uuid())::text} DEFAULT; the INSERT OMITS {@code id} and appends
 * {@code RETURNING id} to read the database-generated string back ({@code Mono<String>}).
 */
public interface TestRunRowRepository extends ReactiveCrudRepository<TestRunRow, String> {

    /**
     * Insert a freshly-queued run with a DB-generated id (id OMITTED → filled from the column
     * DEFAULT; {@code RETURNING id} reads the generated varchar(36) back). The not-yet-set
     * lifecycle columns ({@code job_name}/{@code started_at}/{@code finished_at}/{@code
     * duration_ms}/{@code report_ref}/{@code error}) are OMITTED (default NULL — the freshly
     * QUEUED shape); the four roll-up counters are seeded 0 as before.
     */
    String INSERT_RETURNING_ID = """
            INSERT INTO test_run \
            (created_at, triggered_by, tier, trigger_source, status, commit_sha, \
             total_tests, passed, failed, skipped) \
            VALUES (:created_at, :triggered_by, :tier, :trigger_source, :status, :commit_sha, \
             :total_tests, :passed, :failed, :skipped) \
            RETURNING id""";

    @Query(INSERT_RETURNING_ID)
    Mono<String> insertReturningId(@Param("created_at") LocalDateTime createdAt,
                                   @Param("triggered_by") String triggeredBy,
                                   @Param("tier") String tier,
                                   @Param("trigger_source") String triggerSource,
                                   @Param("status") String status,
                                   @Param("commit_sha") String commitSha,
                                   @Param("total_tests") int totalTests,
                                   @Param("passed") int passed,
                                   @Param("failed") int failed,
                                   @Param("skipped") int skipped);

    /** Newest-first run history ({@code ORDER BY created_at DESC}). */
    Flux<TestRunRow> findAllByOrderByCreatedAtDesc();

    /** Mark a run RUNNING (state-guarded on QUEUED), record the job name + start clock. */
    String MARK_RUNNING =
            "UPDATE test_run SET status = 'RUNNING', job_name = COALESCE(:job, job_name), "
            + "started_at = now() WHERE id = :id AND status = 'QUEUED'";

    @Modifying
    @Query(MARK_RUNNING)
    Mono<Long> markRunning(String id, String job);

    /** Close out a run terminally with the final roll-up counters + report path. */
    String FINISH =
            "UPDATE test_run SET status = :status, finished_at = now(), total_tests = :total, "
            + "passed = :passed, failed = :failed, skipped = :skipped, "
            + "duration_ms = COALESCE(:dur, duration_ms), report_ref = COALESCE(:ref, report_ref), "
            + "error = :error WHERE id = :id";

    @Modifying
    @Query(FINISH)
    Mono<Long> finish(String id, String status, int total, int passed, int failed, int skipped,
                      Long dur, String ref, String error);

    /** Generic status move (sets finished_at iff the new status is terminal). */
    String UPDATE_STATUS =
            "UPDATE test_run SET status = :status, error = :error, "
            + "finished_at = CASE WHEN :status IN ('COMPLETED','FAILED','ERROR') "
            + "THEN now() ELSE finished_at END WHERE id = :id";

    @Modifying
    @Query(UPDATE_STATUS)
    Mono<Long> updateStatus(String id, String status, String error);
}
