package systems.hugmesh.adminbff.notification.channel;

/**
 * The NEUTRAL message a {@link NotificationChannel} adapter posts as the {@code @system}
 * sender. Composed by {@code NotificationTemplate} from the outbox payload's reason/ttl/
 * target context ONLY — it never carries the acting mod/admin identity (the @system
 * sender is impersonal end to end). {@code category} lets an adapter tailor formatting
 * without changing the neutral wording.
 */
public record ChannelMessage(String category, String title, String body) {
}
