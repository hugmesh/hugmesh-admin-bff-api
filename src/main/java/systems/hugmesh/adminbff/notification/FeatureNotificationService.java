package systems.hugmesh.adminbff.notification;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;

/**
 * Emits FEATURE-AVAILABILITY + INFRA-IMPACTING notification outbox rows (Notifications
 * PR7) — the platform-event triggers that are NOT derived from a desired-state effect
 * (those, e.g. account-restriction, are emitted in the effect's transaction by
 * SuspensionService). A feature toggle / a planned-maintenance infra event has no such
 * effect row, so this service writes the outbox row directly (idempotently), and the
 * existing in-app + external-channel reconcilers fan it out to the neutral {@code @system}
 * sender exactly as any other category.
 *
 * <h3>Neutral payload — no actor</h3>
 * The payload carries ONLY {@code target} (the recipient subject) + an optional
 * {@code reason}/note. Like every notification payload, it NEVER carries the acting
 * admin/superadmin identity — the {@code @system} sender is impersonal and the
 * {@link NotificationTemplate} composes a neutral message from these fields.
 *
 * <h3>Idempotent + per-domain</h3>
 * Each emit is keyed on a caller-supplied {@code eventKey} (the {@code source_id}) so a
 * retry of the same platform event for the same recipient is a no-op (the outbox
 * {@code UNIQUE(source_table, source_id, category)} guard, surfaced via
 * {@link NotificationOutboxRepository#insertIfAbsent}). The {@code domain} is the caller's
 * validated tenant — never user-settable.
 */
@Service
public class FeatureNotificationService {

    private static final Logger log = LoggerFactory.getLogger(FeatureNotificationService.class);
    private static final ObjectMapper MAPPER = new ObjectMapper();

    private final NotificationOutboxRepository outbox;

    public FeatureNotificationService(NotificationOutboxRepository outbox) {
        this.outbox = outbox;
    }

    /** The kind of platform-event notification to emit. */
    public enum Kind {
        FEATURE_AVAILABILITY(NotificationOutbox.CATEGORY_FEATURE_AVAILABILITY),
        INFRA_IMPACTING(NotificationOutbox.CATEGORY_INFRA_IMPACTING);

        final String category;
        Kind(String category) { this.category = category; }
    }

    /**
     * Idempotently emit a {@code feature-availability} / {@code infra-impacting}
     * notification outbox row for {@code recipientSubject} in {@code domain}. Returns
     * {@code true} iff THIS call inserted the row (a deduped retry returns {@code false}).
     *
     * @param domain           the caller's validated tenant (never user-settable)
     * @param recipientSubject the affected user (the notification recipient + payload target)
     * @param eventKey         a stable key for this platform event (the outbox source_id);
     *                         a retry with the same key is a no-op
     * @param reason           an optional neutral note (NEVER an actor identity)
     */
    public Mono<Boolean> emit(Kind kind, String domain, String recipientSubject,
                              String eventKey, String reason) {
        if (domain == null || domain.isBlank()) {
            // Fail-closed: an unresolved tenant never silently defaults to another brand.
            return Mono.error(new IllegalArgumentException("domain is required"));
        }
        if (recipientSubject == null || recipientSubject.isBlank()) {
            return Mono.error(new IllegalArgumentException("recipientSubject is required"));
        }
        String sourceId = (eventKey == null || eventKey.isBlank())
                ? UUID.randomUUID().toString() : eventKey;
        String payload = payload(recipientSubject, reason);
        return outbox.insertIfAbsent(domain, NotificationOutbox.SOURCE_PLATFORM_EVENT,
                        sourceId, kind.category, payload)
                .map(rows -> rows != null && rows > 0)
                .doOnSuccess(inserted -> log.info("[notify-trigger] {} domain={} recipient={} key={} inserted={}",
                        kind.category, domain, recipientSubject, sourceId, inserted));
    }

    /** Neutral payload: target + optional reason ONLY — never an actor. */
    private static String payload(String target, String reason) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("target", target);
        if (reason != null && !reason.isBlank()) {
            body.put("reason", reason);
        }
        try {
            return MAPPER.writeValueAsString(body);
        } catch (Exception e) {
            // The map holds only Strings — serialisation cannot realistically fail.
            return "{\"target\":\"" + target.replace("\"", "\\\"") + "\"}";
        }
    }
}
