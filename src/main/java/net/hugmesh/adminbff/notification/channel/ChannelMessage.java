package net.hugmesh.adminbff.notification.channel;

/**
 * The NEUTRAL message a {@link NotificationChannel} adapter posts as the {@code @system}
 * sender. Composed by {@code NotificationTemplate} from the outbox payload's reason/ttl/
 * target context ONLY — it never carries the acting mod/admin identity (the @system
 * sender is impersonal end to end). {@code category} lets an adapter tailor formatting
 * without changing the neutral wording.
 *
 * <p>{@code deliveryKey} is the stable id of the outbox row being delivered (or null). A
 * transport that supports idempotent submission (the Matrix txn id) derives it from this,
 * so a retry after a lost reply is deduplicated by a homeserver that honours the txn id
 * (tested against the fake only). It identifies a row,
 * never a person, and never the acting mod/admin.
 */
public record ChannelMessage(String category, String title, String body, String deliveryKey) {

    /** A message with no delivery key. */
    public ChannelMessage(String category, String title, String body) {
        this(category, title, body, null);
    }
}
