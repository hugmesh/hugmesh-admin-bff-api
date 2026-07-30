package systems.hugmesh.adminbff.testreports;

import org.springframework.data.annotation.Id;
import org.springframework.data.annotation.PersistenceCreator;
import org.springframework.data.annotation.Transient;
import org.springframework.data.domain.Persistable;
import org.springframework.data.relational.core.mapping.Column;
import org.springframework.data.relational.core.mapping.Table;

import java.time.LocalDateTime;
import java.time.ZoneOffset;

/**
 * One row of {@code test_run_result} (Liquibase changeset 070) — the per-(suite,role)
 * roll-up for a run. PK is a {@code varchar(36)} app-generated UUID string;
 * {@code updated_at} is {@code timestamp} -> {@link LocalDateTime}. {@link TestRunResult}
 * stays the JSON projection; {@link TestRunRepository} maps between the two. Implements
 * {@link Persistable} so a new result row INSERTs.
 */
@Table("test_run_result")
public record TestRunResultRow(
        @Id @Column("id") String id,
        @Column("run_id") String runId,
        @Column("suite") String suite,
        @Column("role") String role,
        @Column("state") String state,
        @Column("passed") int passed,
        @Column("failed") int failed,
        @Column("skipped") int skipped,
        @Column("duration_ms") Long durationMs,
        @Column("updated_at") LocalDateTime updatedAt,
        @Transient boolean isNew) implements Persistable<String> {

    @PersistenceCreator
    public TestRunResultRow(String id, String runId, String suite, String role, String state,
                            int passed, int failed, int skipped, Long durationMs, LocalDateTime updatedAt) {
        this(id, runId, suite, role, state, passed, failed, skipped, durationMs, updatedAt, false);
    }

    TestRunResult toDomain() {
        return new TestRunResult(id, runId, suite, role, state, passed, failed, skipped, durationMs,
                updatedAt == null ? null : updatedAt.toInstant(ZoneOffset.UTC));
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
