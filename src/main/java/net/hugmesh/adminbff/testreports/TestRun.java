package net.hugmesh.adminbff.testreports;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.time.Instant;

/**
 * One row of {@code test_run} (Liquibase changeset 070) — the durable record of a
 * test-architecture run (LEAN on fe/be/pki-ready, HEAVY on x86-attach). This is the
 * JSON shape the admin-ui Test-Reports recent-runs table reads.
 *
 * <p>Shaped like {@link net.hugmesh.adminbff.backup.BackupRecord}: an
 * app-generated {@code varchar(36)} id, a {@code created_at} default, closed-enum
 * {@code tier} / {@code status} / {@code triggerSource} columns mirrored by DB CHECK
 * constraints (the platform API&lt;-&gt;DB parity rule), and the per-run roll-up
 * counters the runner's {@code summary.json} emits.
 *
 * <p>Security: {@code reportRef} is only a PVC-relative bundle path — never a secret.
 * The stored artifacts are scrubbed at write-time (the test-runner) AND re-scrubbed
 * at read-time ({@link TestReportArchive}); no tokens/passwords are ever persisted
 * on this row.
 */
public record TestRun(
        String id,
        @JsonProperty("created_at") Instant createdAt,
        @JsonProperty("triggered_by") String triggeredBy,
        String tier,
        @JsonProperty("trigger_source") String triggerSource,
        String status,
        @JsonProperty("commit_sha") String commitSha,
        @JsonProperty("job_name") String jobName,
        @JsonProperty("started_at") Instant startedAt,
        @JsonProperty("finished_at") Instant finishedAt,
        @JsonProperty("total_tests") int totalTests,
        int passed,
        int failed,
        int skipped,
        @JsonProperty("duration_ms") Long durationMs,
        @JsonProperty("report_ref") String reportRef,
        String error) {

    // ── tier vocabulary (DB CHECK ck_test_run_tier) ────────────────────────
    public static final String TIER_LEAN = "LEAN";
    public static final String TIER_HEAVY = "HEAVY";

    // ── status lifecycle (DB CHECK ck_test_run_status) ─────────────────────
    public static final String STATUS_QUEUED = "QUEUED";
    public static final String STATUS_RUNNING = "RUNNING";
    public static final String STATUS_COMPLETED = "COMPLETED";
    public static final String STATUS_FAILED = "FAILED";
    /** Harness/peer-pairing broken = inconclusive (distinct from FAILED = a real
     *  assertion failed). The federation-liveness precondition ERRORs the suite. */
    public static final String STATUS_ERROR = "ERROR";

    // ── trigger provenance (DB CHECK ck_test_run_trigger_source) ───────────
    public static final String SOURCE_ADMIN = "ADMIN";
    public static final String SOURCE_ARGOCD = "ARGOCD";
    public static final String SOURCE_HEAVY_ATTACH = "HEAVY_ATTACH";

    /** True once the run has reached a terminal status (no more SSE events). */
    public boolean terminal() {
        return STATUS_COMPLETED.equals(status)
                || STATUS_FAILED.equals(status)
                || STATUS_ERROR.equals(status);
    }
}
