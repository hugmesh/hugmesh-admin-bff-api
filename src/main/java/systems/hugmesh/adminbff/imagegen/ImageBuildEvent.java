package systems.hugmesh.adminbff.imagegen;

/**
 * One progress event streamed (SSE) for a running image-generation build. Mirrors the
 * {@link systems.hugmesh.adminbff.testreports.TestRunEvent} shape so the admin-ui can
 * reuse the test-reports / backup SSE rendering: {@code message} into an aria-live region,
 * {@code phase} drives the per-phase widgets, {@code done}/{@code error} are the terminal
 * markers, and {@code percent} the progress bar.
 *
 * <p>An image build is a linear phase progression (queued &rarr; partition / debootstrap /
 * kernel / mesh-seed / package / finalize &rarr; complete), so unlike a test run it carries
 * a single coarse {@code phase} rather than a (suite, role) matrix.
 *
 * <p>SECURITY: this event NEVER carries secret material. {@code imageRef} / {@code keysRef}
 * are non-secret POINTERS only (a build-artifacts location); a private dial key never appears
 * here, in a log, or in a {@code toString}.
 */
public record ImageBuildEvent(
        String buildId,
        String phase,
        int percent,
        String message,
        String imageRef,
        String keysRef,
        boolean done,
        String error) {

    public static final String PHASE_QUEUED = "queued";
    public static final String PHASE_RUNNING = "running";
    public static final String PHASE_COMPLETE = "complete";
    public static final String PHASE_ERROR = "error";

    /** A coarse progress event (a phase started / advanced). */
    public static ImageBuildEvent progress(String buildId, int percent, String message) {
        return new ImageBuildEvent(buildId, PHASE_RUNNING, percent, message, null, null, false, null);
    }

    /** Terminal: the build COMPLETED — {@code imageRef} (and optionally {@code keysRef}) are the
     *  non-secret artifact pointers the admin-ui turns into download links. */
    public static ImageBuildEvent complete(String buildId, String imageRef, String keysRef, String message) {
        return new ImageBuildEvent(buildId, PHASE_COMPLETE, 100, message, imageRef, keysRef, true, null);
    }

    /** Terminal: the build FAILED/ERRORed (inconclusive — e.g. the Job could not be launched). */
    public static ImageBuildEvent failed(String buildId, String error) {
        return new ImageBuildEvent(buildId, PHASE_ERROR, 100, error, null, null, true, error);
    }
}
