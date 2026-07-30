package systems.hugmesh.adminbff.web.dto;

import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

/**
 * Body for {@code POST /bff/admin/test-reports/run} (trigger a test run on-demand).
 *
 * <p>{@code tier} is {@code LEAN} (fe/be/pki-ready, Pi-friendly) or {@code HEAVY}
 * (x86-attach: kafka + clickhouse + observability paths) — the closed
 * {@link systems.hugmesh.adminbff.testreports.TestRun} {@code tier} vocabulary,
 * mirrored by the {@code ck_test_run_tier} DB CHECK. The optional {@code commitSha}
 * pins the suite/runner-image revision for provenance (recorded on the
 * {@code test_run} row); when omitted the orchestrator records the runner image's
 * own build commit.
 *
 * <p>Unlike a backup there is no secret on this request — the run is launched with
 * the dedicated {@code test-runner} ServiceAccount; the runner authenticates to the
 * ingest endpoint with its own pre-minted token, never a value carried here.
 */
public record StartTestRunRequest(
        @Pattern(regexp = "(?i)LEAN|HEAVY", message = "tier must be LEAN or HEAVY")
        String tier,

        @Size(max = 64, message = "commitSha is too long")
        @Pattern(regexp = "[0-9a-fA-F]{0,64}", message = "commitSha must be a hex git sha")
        String commitSha) {

    /** The requested tier, defaulting to LEAN when unset. */
    public String tierOrLean() {
        return (tier == null || tier.isBlank()) ? "LEAN" : tier.trim().toUpperCase();
    }
}
