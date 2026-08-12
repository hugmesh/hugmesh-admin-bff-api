package net.hugmesh.adminbff.testreports;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.time.Instant;

/**
 * One row of {@code test_run_result} (Liquibase changeset 070) — a per-(suite,role)
 * pass/fail/skip roll-up for the Test-Reports detail matrix and the durable side of
 * the live SSE dashboard. The test-runner POSTs these to the event-ingest endpoint
 * as suites finish; the orchestrator upserts them (unique on run+suite+role) and
 * replays them to a reconnecting admin so the per-suite/per-role matrix survives a
 * pod restart (the SSE replay buffer is bounded + live-only — the durable matrix is
 * here).
 *
 * <p>{@code role} is the role a test maps to via the spec annotation convention
 * ({@code test.info().annotations role=...}); {@code ALL} for suite-level / unscoped
 * rows. The admin-ui renders one widget per (suite,role) keyed by {@code state}.
 */
public record TestRunResult(
        String id,
        @JsonProperty("run_id") String runId,
        String suite,
        String role,
        String state,
        int passed,
        int failed,
        int skipped,
        @JsonProperty("duration_ms") Long durationMs,
        @JsonProperty("updated_at") Instant updatedAt) {

    /** Suite/role-unscoped marker for the {@code role} column. */
    public static final String ROLE_ALL = "ALL";

    // ── per-(suite,role) state (DB CHECK ck_test_run_result_state) ─────────
    public static final String STATE_RUNNING = "running";
    public static final String STATE_PASSED = "passed";
    public static final String STATE_FAILED = "failed";
    public static final String STATE_SKIPPED = "skipped";
}
