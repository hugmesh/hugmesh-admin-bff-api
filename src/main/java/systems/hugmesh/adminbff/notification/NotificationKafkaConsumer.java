package systems.hugmesh.adminbff.notification;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.kafka.clients.consumer.ConsumerRecord;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.kafka.annotation.KafkaListener;
import org.springframework.stereotype.Component;

/**
 * The Kafka FAST-PATH for notifications (Notifications PR7) — gated behind
 * {@code app.kafka.enabled} (the SAME flag as the usage bus; default false → a broker-less
 * dev/test run never registers this listener).
 *
 * <h3>The outbox is the authoritative backstop — Kafka never bypasses the delivered-truth</h3>
 * When a producer (this BFF's own effect writers, or another service) emits a notification
 * event, this consumer IDEMPOTENTLY ENSURES the {@code notification_outbox} row exists
 * (via {@link NotificationOutboxRepository#insertIfAbsent}, deduped on the
 * {@code (source_table, source_id, category)} natural key). It does NOT itself deliver. The
 * existing SQL-tail reconcilers (in-app + external channels) then deliver FROM the outbox
 * exactly as before, and the per-channel {@code notification_delivery} UNIQUE(outbox_id,
 * channel) guard is the single delivered-truth.
 *
 * <p>Why this is never lossy and never double-delivers:
 * <ul>
 *   <li><b>never lossy</b> — even if Kafka is down or an event is dropped, the
 *       transactional outbox already holds the row (the lossless backstop the effect write
 *       creates in-tx, PR2); the SQL-tail still delivers it. Kafka only makes the outbox
 *       population/notice faster, it is never the sole record.</li>
 *   <li><b>never double-delivers</b> — a Kafka redelivery (at-least-once) re-runs
 *       {@code insertIfAbsent}, which is a no-op (UNIQUE on the natural key); and the
 *       delivery itself is guarded by {@code notification_delivery}'s per-channel UNIQUE,
 *       so a Kafka-accelerated and a tail-driven delivery converge on ONE row.</li>
 * </ul>
 *
 * <p>Runs on the spring-kafka container thread (blocking by nature); the reactive
 * {@code insertIfAbsent} is {@code block()}ed here so an offset is committed only after a
 * successful ensure (at-least-once), on the container thread, never the WebFlux event loop.
 */
@Component
@ConditionalOnProperty(name = "app.kafka.enabled", havingValue = "true")
public class NotificationKafkaConsumer {

    private static final Logger log = LoggerFactory.getLogger(NotificationKafkaConsumer.class);
    private static final ObjectMapper MAPPER = new ObjectMapper();

    private final NotificationOutboxRepository outbox;

    public NotificationKafkaConsumer(NotificationOutboxRepository outbox) {
        this.outbox = outbox;
    }

    @KafkaListener(
            topics = "${app.kafka.topic.notification-events:notification_events}",
            groupId = "${app.kafka.consumer.notification-group-id:hugmesh-admin-bff-api-notifications}")
    public void onNotificationEvent(ConsumerRecord<String, String> record) {
        Event e = parse(record.value());
        if (e == null) {
            return;
        }
        try {
            // Idempotent ensure — a redelivery is a no-op (UNIQUE on the natural key).
            outbox.insertIfAbsent(e.domain(), e.sourceTable(), e.sourceId(), e.category(), e.payload())
                    .block();
        } catch (Exception ex) {
            // Re-throw so spring-kafka does NOT commit the offset and redelivers (the
            // outbox + delivery guards make a redelivery safe). Never lossy.
            log.warn("[notify-kafka] outbox ensure failed, will redeliver: {}", ex.toString());
            throw ex;
        }
    }

    /**
     * Parse a notification event. Requires {@code domain}, {@code sourceTable},
     * {@code sourceId}, {@code category}; {@code payload} is optional (reason/ttl/target
     * JSON — and like every notification payload it must NOT carry the actor). Garbage /
     * a missing required field is dropped (logged) rather than crashing the listener.
     */
    Event parse(String value) {
        if (value == null || value.isBlank()) {
            return null;
        }
        try {
            JsonNode n = MAPPER.readTree(value);
            String domain = text(n, "domain");
            String sourceTable = text(n, "sourceTable");
            String sourceId = text(n, "sourceId");
            String category = text(n, "category");
            if (domain == null || sourceTable == null || sourceId == null || category == null) {
                log.warn("[notify-kafka] dropping event missing a required field: {}", value);
                return null;
            }
            String payload = n.hasNonNull("payload")
                    ? (n.get("payload").isObject() ? n.get("payload").toString() : n.get("payload").asText())
                    : null;
            return new Event(domain, sourceTable, sourceId, category, payload);
        } catch (Exception ex) {
            log.warn("[notify-kafka] dropping unparseable notification event: {}", ex.toString());
            return null;
        }
    }

    private static String text(JsonNode n, String field) {
        JsonNode v = n.get(field);
        if (v == null || v.isNull()) {
            return null;
        }
        String s = v.asText();
        return s.isBlank() ? null : s;
    }

    /** A parsed notification event (the Kafka fast-path's payload). */
    record Event(String domain, String sourceTable, String sourceId, String category, String payload) {}
}
