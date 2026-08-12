package net.hugmesh.adminbff.announcement;

/**
 * The outcome of propagating (or removing) an announcement on akkoma (the
 * Mastodon-API server), carried back to the service so the action is auditable
 * regardless of whether the external call was actually made. Mirrors the
 * hugmesh-mod-bff-api {@code BlockOutcome} stub-seam convention.
 *
 * <ul>
 *   <li>{@code STUBBED} ({@link #stubbed(String)}) — the external admin HTTP call
 *       was deliberately NOT made (akkoma admin is unconfigured /
 *       {@code external.mastodon.enabled=false}); {@link #ref()} is null. The
 *       announcement is still recorded locally and fully auditable.</li>
 *   <li>{@code OK} ({@link #created(String)}) — the akkoma announcement was created;
 *       {@link #ref()} is the new akkoma announcement id to persist as
 *       {@code akkoma_ref} (used to remove it later). For a removal the OK ref is
 *       null.</li>
 *   <li>{@code degraded:<reason>} ({@link #degraded(String)}) — the call was
 *       attempted and failed; never hard-fail the publish.</li>
 * </ul>
 */
public record AkkomaOutcome(String result, String ref) {

    public static AkkomaOutcome stubbed() {
        return new AkkomaOutcome("stubbed", null);
    }

    /** akkoma announcement created — {@code ref} is the id to persist as akkoma_ref. */
    public static AkkomaOutcome created(String ref) {
        return new AkkomaOutcome("ok", ref);
    }

    /** A successful removal / non-creating OK with no ref. */
    public static AkkomaOutcome ok() {
        return new AkkomaOutcome("ok", null);
    }

    public static AkkomaOutcome degraded(String reason) {
        return new AkkomaOutcome("degraded:" + reason, null);
    }

    public boolean isStubbed() {
        return "stubbed".equals(result);
    }

    public boolean isOk() {
        return "ok".equals(result);
    }
}
