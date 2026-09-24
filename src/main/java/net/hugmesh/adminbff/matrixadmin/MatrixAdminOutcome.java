package net.hugmesh.adminbff.matrixadmin;

/**
 * The outcome of one ADMIN-only {@code !admin users deactivate} attempt against tuwunel,
 * recorded on the {@code matrix_admin_deactivate_proposal} row and returned to the caller.
 *
 * <p>Ported from hugmesh-mod-bff-api {@code BlockOutcome} (the transport's original home)
 * with the vocabulary this path can actually produce. There is deliberately NO {@code ok}:
 *
 * <ul>
 *   <li>{@code stubbed} — the transport is dark ({@code matrix-admin.enabled=false}); NO HTTP
 *       was issued.</li>
 *   <li>{@code posted:<event_id>} — the command MESSAGE was accepted into the admin room.
 *       tuwunel's in-process admin bot applies it ASYNCHRONOUSLY and its reply is not read
 *       back yet, so this is "sent", never "applied".</li>
 *   <li>{@code degraded:<reason>} — the post was attempted and failed, or could not be
 *       attempted (no admin token, admin room unresolvable, non-2xx, timeout, a target that
 *       is not a plain MXID).</li>
 * </ul>
 */
public record MatrixAdminOutcome(String result) {

    public static final MatrixAdminOutcome STUBBED = new MatrixAdminOutcome("stubbed");

    public static MatrixAdminOutcome posted(String eventId) {
        return new MatrixAdminOutcome("posted:" + eventId);
    }

    public static MatrixAdminOutcome degraded(String reason) {
        return new MatrixAdminOutcome("degraded:" + reason);
    }

    public boolean isPosted() {
        return result != null && result.startsWith("posted:");
    }

    public boolean isStubbed() {
        return "stubbed".equals(result);
    }

    public boolean isDegraded() {
        return result != null && result.startsWith("degraded:");
    }
}
