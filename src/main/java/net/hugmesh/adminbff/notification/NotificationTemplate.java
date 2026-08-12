package net.hugmesh.adminbff.notification;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * Composes a NEUTRAL {@code title} + {@code body} for an in-app notification from a
 * {@code notification_outbox} row, per category. This is the single place the
 * {@code @system} sender's wording lives.
 *
 * <p><b>Identity rule (load-bearing).</b> The template draws ONLY from the outbox
 * payload's {@code reason} / {@code ttl_seconds} / {@code permanent} fields (the
 * payload, by PR2's {@code AccountRestrictionPayload} invariant, NEVER contains the
 * acting mod/admin identity). The wording is impersonal — "Your account access changed",
 * never "Moderator X restricted you" — so the neutral-sender posture holds end to end.
 *
 * <p>A blank/blank-reason or an unknown category degrades to a safe generic message
 * rather than leaking raw payload or throwing out of a reconcile tick.
 */
public final class NotificationTemplate {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private NotificationTemplate() {
    }

    /** The composed neutral message (title + body). */
    public record Message(String title, String body) {
    }

    /**
     * Build the neutral message for an outbox row. Switches on {@code category}; the
     * body is derived from the payload's reason/ttl WITHOUT the actor.
     *
     * @param category the outbox category (e.g. {@code account-restriction})
     * @param payload  the outbox payload JSON (reason/ttl/target/role — never the actor)
     */
    public static Message render(String category, String payload) {
        JsonNode p = parse(payload);
        return switch (category == null ? "" : category) {
            case NotificationOutbox.CATEGORY_ACCOUNT_RESTRICTION -> accountRestriction(p);
            case "role-change" -> new Message(
                    "Your account roles changed",
                    "Your access roles on this service were updated." + reasonSuffix(p));
            case "infra-impacting" -> new Message(
                    "A service you use is affected",
                    "A platform change may temporarily affect a service you use." + reasonSuffix(p));
            case "feature-availability" -> new Message(
                    "Feature availability changed",
                    "The availability of a feature on this service has changed." + reasonSuffix(p));
            case NotificationOutbox.CATEGORY_BACKUP_STARTED -> new Message(
                    "A backup has started",
                    "A backup of this service's data has started." + reasonSuffix(p));
            case NotificationOutbox.CATEGORY_RESTORE_STARTED -> new Message(
                    "A restore has started",
                    "A restore of this service's data from a backup has started." + reasonSuffix(p));
            default -> new Message(
                    "A notification about your account",
                    "There is an update related to your account." + reasonSuffix(p));
        };
    }

    /** account-restriction: neutral "access changed" + permanent-vs-until-expiry from ttl. */
    private static Message accountRestriction(JsonNode p) {
        boolean permanent = p.path("permanent").asBoolean(false)
                || p.path("ttl_seconds").isNull() || p.path("ttl_seconds").isMissingNode();
        long ttl = p.path("ttl_seconds").asLong(0L);
        StringBuilder body = new StringBuilder("Your account access on this service has changed.");
        if (!permanent && ttl > 0) {
            body.append(" This restriction is temporary and lasts about ")
                    .append(humanDuration(ttl)).append('.');
        } else {
            body.append(" This restriction does not have a set end time.");
        }
        body.append(reasonSuffix(p));
        body.append(" If you believe this is a mistake, you can appeal through the support contact.");
        return new Message("Your account access changed", body.toString());
    }

    /** Append " Reason: <reason>." iff the payload carries a non-blank reason. */
    private static String reasonSuffix(JsonNode p) {
        String reason = p.path("reason").asText(null);
        if (reason == null || reason.isBlank()) {
            return "";
        }
        return " Reason: " + reason.trim() + ".";
    }

    /** Coarse human duration from seconds (hours/days) — no precise clock, just context. */
    private static String humanDuration(long seconds) {
        long days = seconds / 86_400;
        if (days >= 1) {
            return days + (days == 1 ? " day" : " days");
        }
        long hours = seconds / 3_600;
        if (hours >= 1) {
            return hours + (hours == 1 ? " hour" : " hours");
        }
        long minutes = Math.max(1, seconds / 60);
        return minutes + (minutes == 1 ? " minute" : " minutes");
    }

    private static JsonNode parse(String payload) {
        if (payload == null || payload.isBlank()) {
            return MAPPER.createObjectNode();
        }
        try {
            return MAPPER.readTree(payload);
        } catch (Exception e) {
            // A malformed payload must not break message composition — degrade to empty.
            return MAPPER.createObjectNode();
        }
    }
}
