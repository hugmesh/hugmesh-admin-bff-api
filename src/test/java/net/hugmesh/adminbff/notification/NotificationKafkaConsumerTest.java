package net.hugmesh.adminbff.notification;

import org.apache.kafka.clients.consumer.ConsumerRecord;
import org.junit.jupiter.api.Test;
import reactor.core.publisher.Mono;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit coverage for the Kafka fast-path (Notifications PR7): a notification event
 * IDEMPOTENTLY ENSURES the outbox row (never delivers directly, never double-inserts).
 */
class NotificationKafkaConsumerTest {

    private static ConsumerRecord<String, String> rec(String value) {
        return new ConsumerRecord<>("notification_events", 0, 0L, "k", value);
    }

    // ── a valid event ensures the outbox row (idempotent insert) ─────────────
    @Test
    void validEvent_ensuresOutboxRow() {
        NotificationOutboxRepository outbox = mock(NotificationOutboxRepository.class);
        when(outbox.insertIfAbsent(eq("brandx"), eq("access_suspension"), eq("src-1"),
                eq("account-restriction"), any())).thenReturn(Mono.just(1L));
        NotificationKafkaConsumer c = new NotificationKafkaConsumer(outbox);

        c.onNotificationEvent(rec("{\"domain\":\"brandx\",\"sourceTable\":\"access_suspension\","
                + "\"sourceId\":\"src-1\",\"category\":\"account-restriction\","
                + "\"payload\":{\"target\":\"alice\",\"reason\":\"abuse\"}}"));

        verify(outbox, times(1)).insertIfAbsent(eq("brandx"), eq("access_suspension"), eq("src-1"),
                eq("account-restriction"), any());
    }

    // ── a redelivery is a no-op at the repo (UNIQUE on the natural key) ──────
    @Test
    void redelivery_isNoOp_viaInsertIfAbsent() {
        NotificationOutboxRepository outbox = mock(NotificationOutboxRepository.class);
        // insertIfAbsent returns 0 on the dedup (already present) — the consumer does not
        // treat that as an error (no re-throw → offset commits).
        when(outbox.insertIfAbsent(any(), any(), any(), any(), any())).thenReturn(Mono.just(0L));
        NotificationKafkaConsumer c = new NotificationKafkaConsumer(outbox);

        c.onNotificationEvent(rec("{\"domain\":\"brandx\",\"sourceTable\":\"platform_event\","
                + "\"sourceId\":\"e1\",\"category\":\"feature-availability\"}"));

        verify(outbox).insertIfAbsent(eq("brandx"), eq("platform_event"), eq("e1"),
                eq("feature-availability"), any());
    }

    // ── garbage / missing required field is dropped, never ensures a row ─────
    @Test
    void missingRequiredField_isDropped_andNeverEnsures() {
        NotificationOutboxRepository outbox = mock(NotificationOutboxRepository.class);
        NotificationKafkaConsumer c = new NotificationKafkaConsumer(outbox);

        // missing category
        c.onNotificationEvent(rec("{\"domain\":\"brandx\",\"sourceTable\":\"t\",\"sourceId\":\"s\"}"));
        // unparseable
        c.onNotificationEvent(rec("not json"));
        // empty
        c.onNotificationEvent(rec(""));

        verify(outbox, never()).insertIfAbsent(any(), any(), any(), any(), any());
    }

    // ── parse: a JSON-object payload is serialised back to a JSON string ─────
    @Test
    void parse_objectPayload_isCarriedAsJsonString() {
        NotificationKafkaConsumer c = new NotificationKafkaConsumer(mock(NotificationOutboxRepository.class));
        NotificationKafkaConsumer.Event e = c.parse("{\"domain\":\"d\",\"sourceTable\":\"t\","
                + "\"sourceId\":\"s\",\"category\":\"c\",\"payload\":{\"target\":\"alice\"}}");
        assertThat(e).isNotNull();
        assertThat(e.payload()).contains("\"target\"").contains("alice");
    }
}
