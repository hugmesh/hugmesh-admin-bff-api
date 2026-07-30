package systems.hugmesh.adminbff.web.dto;

import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.PositiveOrZero;
import jakarta.validation.constraints.Size;

/**
 * The internal event-ingest payload the test-runner Job POSTs to
 * {@code POST /bff/admin/test-reports/{runId}/ingest} as suites start / finish and
 * when the whole run terminates. This is the REAL event path the design calls for —
 * the runner (in-cluster) feeds the BFF's bounded SSE sink, replacing the backup
 * orchestrator's synthetic phase progression (which is a documented dev-only stand-in).
 *
 * <p>Two event kinds, distinguished by {@code kind}:
 * <ul>
 *   <li>{@code SUITE} — a per-(suite,role) update. {@code suite} required;
 *       {@code role} defaults to {@code ALL}; {@code state} is the per-(suite,role)
 *       state; the upsert writes a {@code test_run_result} row + fans an SSE event.</li>
 *   <li>{@code RUN} — a run-level terminal roll-up. {@code state} {@code passed}/
 *       {@code failed}/{@code error}; the totals close out the {@code test_run} row.</li>
 * </ul>
 *
 * <p>SECURITY: this endpoint is admin-gated (defence-in-depth like every other
 * {@code /bff/admin/**} path) AND the runner carries its own pre-minted token; the
 * payload is data-only (counts + labels) — never a secret. {@code message} is
 * length-bounded; the orchestrator does not log it verbatim.
 */
public record TestRunIngestRequest(
        @NotBlank(message = "kind is required")
        @Pattern(regexp = "SUITE|RUN", message = "kind must be SUITE or RUN")
        String kind,

        @Size(max = 255, message = "suite is too long")
        String suite,

        @Size(max = 64, message = "role is too long")
        String role,

        @NotBlank(message = "state is required")
        @Pattern(regexp = "running|passed|failed|skipped|error",
                message = "state must be running, passed, failed, skipped or error")
        String state,

        @PositiveOrZero(message = "passed must be >= 0")
        @Max(value = 1_000_000, message = "passed is implausibly large")
        int passed,

        @PositiveOrZero(message = "failed must be >= 0")
        @Max(value = 1_000_000, message = "failed is implausibly large")
        int failed,

        @PositiveOrZero(message = "skipped must be >= 0")
        @Max(value = 1_000_000, message = "skipped is implausibly large")
        int skipped,

        @PositiveOrZero(message = "percent must be >= 0")
        @Max(value = 100, message = "percent must be <= 100")
        int percent,

        Long durationMs,

        @Size(max = 1000, message = "message is too long")
        String message) {

    public boolean isRunLevel() {
        return "RUN".equals(kind);
    }
}
