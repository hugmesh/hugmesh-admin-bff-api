package systems.hugmesh.adminbff.testreports;

/**
 * One progress event streamed (SSE) for a running test architecture run. Mirrors
 * the {@link systems.hugmesh.adminbff.backup.JobEvent} shape so the admin-ui can
 * reuse the {@code BackupController.events} rendering: {@code message} into an
 * aria-live region, {@code suite} + {@code role} + {@code state} drive the
 * per-suite/per-role widgets, {@code done}/{@code error} are the terminal markers.
 *
 * <p>Unlike a backup (one linear phase progression), a run fans out over many
 * suites and roles, so the event carries {@code suite} + {@code role} (the spec
 * annotation convention {@code role=...}) and a per-(suite,role) {@code state}
 * ({@code running|passed|failed|skipped}) plus the rolling {@code passed}/
 * {@code failed}/{@code skipped} totals so a late subscriber sees the live tally.
 */
public record TestRunEvent(
        String runId,
        String suite,
        String role,
        String state,
        int passed,
        int failed,
        int skipped,
        int percent,
        String message,
        boolean done,
        String error) {

    // ── per-(suite,role) state (matches TestRunResult.STATE_*) ─────────────
    public static final String STATE_RUNNING = "running";
    public static final String STATE_PASSED = "passed";
    public static final String STATE_FAILED = "failed";
    public static final String STATE_SKIPPED = "skipped";

    /** A per-(suite,role) progress event (a suite started / finished). */
    public static TestRunEvent suite(String runId, String suite, String role, String state,
                                     int passed, int failed, int skipped, int percent, String message) {
        return new TestRunEvent(runId, suite, role, state, passed, failed, skipped,
                percent, message, false, null);
    }

    /** A coarse run-level progress event (no specific suite). */
    public static TestRunEvent progress(String runId, int percent, String message) {
        return new TestRunEvent(runId, null, null, STATE_RUNNING, 0, 0, 0,
                percent, message, false, null);
    }

    /** Terminal: the run completed (passed/failed counts are the final totals). */
    public static TestRunEvent complete(String runId, int passed, int failed, int skipped, String message) {
        return new TestRunEvent(runId, null, null,
                failed == 0 ? STATE_PASSED : STATE_FAILED,
                passed, failed, skipped, 100, message, true, null);
    }

    /** Terminal: the run/harness ERRORed (inconclusive — e.g. peer pairing broken). */
    public static TestRunEvent failed(String runId, String error) {
        return new TestRunEvent(runId, null, null, STATE_FAILED, 0, 0, 0,
                100, error, true, error);
    }
}
