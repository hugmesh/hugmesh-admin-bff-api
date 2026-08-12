package net.hugmesh.adminbff.testreports;

import org.springframework.data.r2dbc.repository.Modifying;
import org.springframework.data.r2dbc.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.time.LocalDateTime;

/**
 * Reactive (R2DBC) Spring Data store for {@code test_run_result} (changeset 070). The
 * per-run matrix read + the (run,suite,role) existence lookup are derived finders; the
 * COALESCE partial UPDATE is an {@code @Query} static-final constant. The {@link
 * TestRunRepository} facade composes these + the INSERT below into the portable upsert.
 *
 * <p>DB-GENERATED PK (changelog 200): the varchar(36) {@code id} carries a
 * {@code (gen_random_uuid())::text} DEFAULT; the upsert's INSERT branch OMITS {@code id}
 * and appends {@code RETURNING id} to read the database-generated string back
 * ({@code Mono<String>}).
 */
public interface TestRunResultRowRepository extends ReactiveCrudRepository<TestRunResultRow, String> {

    /**
     * Insert a new per-(suite,role) result with a DB-generated id (the upsert's INSERT
     * branch): {@code id} is OMITTED → filled from the column DEFAULT; {@code RETURNING id}
     * reads the generated varchar(36) back. The supplied columns match the {@link
     * TestRunResultRow} column order (id excluded); {@code duration_ms} is nullable.
     */
    String INSERT_RETURNING_ID = """
            INSERT INTO test_run_result \
            (run_id, suite, role, state, passed, failed, skipped, duration_ms, updated_at) \
            VALUES (:run_id, :suite, :role, :state, :passed, :failed, :skipped, \
             :duration_ms, :updated_at) \
            RETURNING id""";

    @Query(INSERT_RETURNING_ID)
    Mono<String> insertReturningId(@Param("run_id") String runId,
                                   @Param("suite") String suite,
                                   @Param("role") String role,
                                   @Param("state") String state,
                                   @Param("passed") int passed,
                                   @Param("failed") int failed,
                                   @Param("skipped") int skipped,
                                   @Param("duration_ms") Long durationMs,
                                   @Param("updated_at") LocalDateTime updatedAt);

    /** The per-(suite,role) matrix for a run, suite-then-role ordered. */
    Flux<TestRunResultRow> findByRunIdOrderBySuiteAscRoleAsc(String runId);

    /** The existing row for (run, suite, role), if any (the upsert lookup). */
    Mono<TestRunResultRow> findByRunIdAndSuiteAndRole(String runId, String suite, String role);

    /** COALESCE partial UPDATE of an existing result row (keep duration when unset). */
    String UPDATE_RESULT =
            "UPDATE test_run_result SET state = :state, passed = :p, failed = :f, skipped = :s, "
            + "duration_ms = COALESCE(:dur, duration_ms), updated_at = now() WHERE id = :id";

    @Modifying
    @Query(UPDATE_RESULT)
    Mono<Long> updateResult(String id, String state, int p, int f, int s, Long dur);
}
