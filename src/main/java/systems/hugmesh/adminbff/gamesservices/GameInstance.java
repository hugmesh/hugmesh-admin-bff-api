package systems.hugmesh.adminbff.gamesservices;

import java.time.Instant;

/**
 * A single {@code game_instance} row — the desired-state record for one per-domain running
 * game-server instance, driving the single-writer reconcile loop (schema in Liquibase
 * {@code db/changelog/091-game-instance.xml}).
 *
 * <p>Modelled EXACTLY on {@link systems.hugmesh.adminbff.suspension.AccessSuspension}:
 * the table is the SOLE source of truth, the loop renders {@code active} rows into the
 * per-domain ConfigMap (ArgoCD applies the Deployment/Service/PVC), and the row is NEVER
 * deleted — {@code terminated} is a CAS so the row stays the audit trail.
 *
 * <ul>
 *   <li>{@code state} — {@code pending} (requested, not yet rendered) / {@code active}
 *       (rendered, running) / {@code suspended} (rendered out, scaled to zero, resumable)
 *       / {@code terminated} (terminal, rendered out).</li>
 *   <li>{@code endingAt} — {@code null} means runs until explicitly stopped; otherwise the
 *       single clock the expiry scan reads (CAS {@code active -> terminated} at TTL).</li>
 *   <li>{@code propagationState} — {@code pending}/{@code applied}/{@code failed}, the
 *       ConfigMap-render-leg result the loop reconciles forward.</li>
 *   <li>{@code ownerSubject} — the creating principal's {@code jwt.getSubject()} (owner ==
 *       subject, fail-closed).</li>
 *   <li>{@code namespace}/{@code nodePort}/{@code consolePath} — allocated by later PRs
 *       (PR5 namespace, PR7 NodePort + console route); nullable here.</li>
 * </ul>
 */
public record GameInstance(
        String id,
        String domain,
        String slug,
        String name,
        String state,
        String propagationState,
        String ownerSubject,
        Instant createdAt,
        Instant endingAt,
        String namespace,
        Integer nodePort,
        String consolePath,
        Instant updatedAt) {

    public static final String STATE_PENDING = "pending";
    public static final String STATE_ACTIVE = "active";
    public static final String STATE_SUSPENDED = "suspended";
    public static final String STATE_TERMINATED = "terminated";

    public static final String PROP_PENDING = "pending";
    public static final String PROP_APPLIED = "applied";
    public static final String PROP_FAILED = "failed";

    /** Non-terminal == occupies the (domain, slug, name) partial-unique slot. */
    public boolean isNonTerminal() {
        return STATE_PENDING.equals(state) || STATE_ACTIVE.equals(state)
                || STATE_SUSPENDED.equals(state);
    }

    /** Rendered into the per-domain ConfigMap == ACTIVE (only active rows are workloads). */
    public boolean isActive() {
        return STATE_ACTIVE.equals(state);
    }

    /** A timed instance whose TTL has passed at {@code now}. */
    public boolean isExpiredAt(Instant now) {
        return endingAt != null && !endingAt.isAfter(now);
    }
}
