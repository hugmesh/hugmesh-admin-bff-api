package net.hugmesh.adminbff.notification;

/**
 * The request body for the user-bff internal in-app notification endpoint
 * (Notifications PR4 part A's contract):
 *
 * <pre>POST {user-bff}/bff/user/internal/notifications
 *   { domain, userSubject, category, title, body, sourceTable, sourceId } -&gt; 200 {delivered, ...}</pre>
 *
 * <p>Built by the {@link NotificationReconciler} from a {@code notification_outbox} row.
 * {@code sourceTable}/{@code sourceId} are the outbox row's natural key — part A uses
 * them as the DETERMINISTIC dedup id on the user-bff side, so a retried call (same
 * outbox row) is idempotent there too (defence-in-depth alongside this side's
 * {@code UNIQUE(outbox_id, channel)} delivery guard).
 *
 * <p><b>Neutral by construction.</b> {@code title}/{@code body} are composed from a
 * per-category neutral template + the outbox payload's reason/ttl ONLY; the acting
 * moderator identity is never present in the outbox payload (PR2 invariant) and so can
 * never reach this body.
 */
public record UserBffNotification(
        String domain,
        String userSubject,
        String category,
        String title,
        String body,
        String sourceTable,
        String sourceId) {
}
