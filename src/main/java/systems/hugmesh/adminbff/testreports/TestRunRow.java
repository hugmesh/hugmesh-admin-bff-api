package systems.hugmesh.adminbff.testreports;

import org.springframework.data.annotation.Id;
import org.springframework.data.annotation.PersistenceCreator;
import org.springframework.data.annotation.Transient;
import org.springframework.data.domain.Persistable;
import org.springframework.data.relational.core.mapping.Column;
import org.springframework.data.relational.core.mapping.Table;

import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneOffset;

/**
 * One row of {@code test_run} (Liquibase changeset 070) — the durable shape for a
 * {@link TestRun}. PK is a {@code varchar(36)} app-generated UUID string; timestamps are
 * {@code timestamp} (no zone) -> {@link LocalDateTime}. {@link TestRun} stays the JSON
 * projection (Instant times); {@link TestRunRepository} maps between the two. Implements
 * {@link Persistable} so a new run INSERTs.
 */
@Table("test_run")
public record TestRunRow(
        @Id @Column("id") String id,
        @Column("created_at") LocalDateTime createdAt,
        @Column("triggered_by") String triggeredBy,
        @Column("tier") String tier,
        @Column("trigger_source") String triggerSource,
        @Column("status") String status,
        @Column("commit_sha") String commitSha,
        @Column("job_name") String jobName,
        @Column("started_at") LocalDateTime startedAt,
        @Column("finished_at") LocalDateTime finishedAt,
        @Column("total_tests") int totalTests,
        @Column("passed") int passed,
        @Column("failed") int failed,
        @Column("skipped") int skipped,
        @Column("duration_ms") Long durationMs,
        @Column("report_ref") String reportRef,
        @Column("error") String error,
        @Transient boolean isNew) implements Persistable<String> {

    @PersistenceCreator
    public TestRunRow(String id, LocalDateTime createdAt, String triggeredBy, String tier,
                      String triggerSource, String status, String commitSha, String jobName,
                      LocalDateTime startedAt, LocalDateTime finishedAt, int totalTests, int passed,
                      int failed, int skipped, Long durationMs, String reportRef, String error) {
        this(id, createdAt, triggeredBy, tier, triggerSource, status, commitSha, jobName, startedAt,
                finishedAt, totalTests, passed, failed, skipped, durationMs, reportRef, error, false);
    }

    private static Instant toInstant(LocalDateTime t) {
        return t == null ? null : t.toInstant(ZoneOffset.UTC);
    }

    TestRun toDomain() {
        return new TestRun(id, toInstant(createdAt), triggeredBy, tier, triggerSource, status, commitSha,
                jobName, toInstant(startedAt), toInstant(finishedAt), totalTests, passed, failed, skipped,
                durationMs, reportRef, error);
    }

    @Override
    public String getId() {
        return id;
    }

    @Override
    public boolean isNew() {
        return isNew;
    }
}
