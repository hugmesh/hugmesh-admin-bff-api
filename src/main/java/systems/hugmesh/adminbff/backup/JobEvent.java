package systems.hugmesh.adminbff.backup;

/**
 * One progress event streamed (SSE) for a running backup or restore. The
 * admin-ui renders {@code message} into an aria-live region and uses
 * {@code phase} + {@code percent} for the progress bar; {@code done}/{@code error}
 * are the terminal markers.
 *
 * <p>{@code phase} is a coarse stage label (e.g. {@code etcd}, {@code postgres},
 * {@code encrypt}, {@code upload}, {@code complete}, {@code error}) matching the
 * worker script's stages, so the UI can show which scope is in flight without
 * parsing the free-text message.
 */
public record JobEvent(
        String jobId,
        String phase,
        int percent,
        String message,
        boolean done,
        String error) {

    public static JobEvent progress(String jobId, String phase, int percent, String message) {
        return new JobEvent(jobId, phase, percent, message, false, null);
    }

    public static JobEvent complete(String jobId, String message) {
        return new JobEvent(jobId, "complete", 100, message, true, null);
    }

    public static JobEvent failed(String jobId, String error) {
        return new JobEvent(jobId, "error", 100, error, true, error);
    }
}
