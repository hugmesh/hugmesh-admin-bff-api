package net.hugmesh.adminbff.forum;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * The outcome of a forum ADMIN-console effect carried back to the controller so the
 * action is auditable (usage-recorded) regardless of whether the external admin call
 * was actually made. Mirrors the announcement {@code AkkomaOutcome} / homeserver
 * {@code HomeserverOutcome} / mod-bff {@code BlockOutcome} stub-seam convention
 * exactly.
 *
 * <ul>
 *   <li>{@code STUBBED} ({@link #stubbed()}) — the external admin call was
 *       deliberately NOT made (the forum-bff {@code /bff/forum/admin/**} seam is
 *       unconfirmed / {@code external.forum.enabled=false}); {@link #payload()} is an
 *       empty map. The admin intent is still recorded + auditable, and the next call
 *       (once the seam is wired on) re-applies it.</li>
 *   <li>{@code OK} ({@link #ok(Map)}) — the forum-bff admin op succeeded;
 *       {@link #payload()} carries the JSON body it returned (stats, the user list,
 *       the created category, …) for the admin-ui to render.</li>
 *   <li>{@code degraded:<reason>} ({@link #degraded(String)}) — the call was
 *       attempted and failed (or the circuit breaker is open); NEVER hard-fail the
 *       admin request. The console shows a degraded notice and the desired state is
 *       reconciled by the forum reconcile Job.</li>
 * </ul>
 *
 * <p>By contract the controller treats only {@link #isOk()} as "applied"; STUBBED and
 * degraded both keep the admin op reconcilable so flipping the seam on later is
 * config-only.
 */
public record ForumOutcome(String result, Map<String, Object> payload) {

    private static final Map<String, Object> EMPTY = Map.of();

    public static ForumOutcome stubbed() {
        return new ForumOutcome("stubbed", EMPTY);
    }

    /** The forum-bff admin op succeeded — {@code payload} is the JSON body it returned. */
    public static ForumOutcome ok(Map<String, Object> payload) {
        return new ForumOutcome("ok", payload == null ? EMPTY : payload);
    }

    /** A successful non-returning OK (ban/unban/install) with no body. */
    public static ForumOutcome ok() {
        return new ForumOutcome("ok", EMPTY);
    }

    public static ForumOutcome degraded(String reason) {
        return new ForumOutcome("degraded:" + reason, EMPTY);
    }

    public boolean isStubbed() {
        return "stubbed".equals(result);
    }

    public boolean isOk() {
        return "ok".equals(result);
    }

    /**
     * The console-facing JSON envelope: always carries the {@code result} marker
     * ({@code ok}/{@code stubbed}/{@code degraded:…}) plus the returned payload merged
     * in, so the admin-ui can render the data AND surface a stubbed/degraded notice.
     */
    public Map<String, Object> asResponse() {
        Map<String, Object> out = new LinkedHashMap<>(payload);
        out.put("result", result);
        return out;
    }
}
