package systems.hugmesh.adminbff.inference;

/**
 * Structured verdict from {@link EdgeAiInferenceClient#triageInfra(String)}.
 *
 * @param available true iff a real edge-AI triage was produced; false for the
 *                  {@link #disabled()} (no edge-AI node) and {@link #degraded(String)}
 *                  (model error / timeout / open circuit) sentinels
 * @param severity  {@code low|medium|high|critical} (or {@code unknown})
 * @param summary   a neutral one-line note — what was seen + how bad (NEVER an actor identity);
 *                  this is what is posted to admins via the notifications subsystem
 * @param raw       the full model reply (kept for audit/UI; null for the sentinels)
 */
public record TriageResult(boolean available, String severity, String summary, String raw) {

    /** No edge-AI node configured (the capability-gating sentinel). */
    public static TriageResult disabled() {
        return new TriageResult(false, "unknown", "edge-AI inference is not enabled on this mesh", null);
    }

    /** Edge-AI node present but the call failed / timed out / circuit is open. */
    public static TriageResult degraded(String why) {
        return new TriageResult(false, "unknown", "edge-AI inference unavailable (" + why + ")", null);
    }

    /** True iff this verdict warrants a high-priority admin alert. */
    public boolean isHighPriority() {
        return available && ("high".equals(severity) || "critical".equals(severity));
    }

    /** The neutral note to carry into the notification payload. */
    public String asNote() {
        return severity.toUpperCase() + " — " + summary;
    }
}
