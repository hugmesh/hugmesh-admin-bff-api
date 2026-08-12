package net.hugmesh.adminbff.usage;

import org.apache.kafka.clients.consumer.ConsumerRecord;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import reactor.core.publisher.Mono;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

/**
 * The @KafkaListener usage consumer: a JSON usage event consumed off the topic is
 * parsed and persisted to ClickHouse via {@link UsageService#insert}. The
 * ClickHouse write is mocked (no live ClickHouse) — this asserts the consume →
 * parse → insert wiring + the JSON contract {actor,role,action,module,ts}.
 */
class UsageEventConsumerTest {

    private final UsageService usage = mock(UsageService.class);
    private final UsageEventConsumer consumer = new UsageEventConsumer(usage);

    private ConsumerRecord<String, String> record(String value) {
        return new ConsumerRecord<>("usage_events", 0, 0L, "actor-key", value);
    }

    @Test
    void onUsageEvent_parsesJsonAndInsertsToClickHouse() {
        when(usage.insert(any())).thenReturn(Mono.empty());
        consumer.onUsageEvent(record(
                "{\"actor\":\"alice\",\"role\":\"admin\",\"action\":\"admin.invite\",\"module\":\"admin-ui\",\"ts\":1717000000000}"));

        ArgumentCaptor<UsageEvent> cap = ArgumentCaptor.forClass(UsageEvent.class);
        verify(usage).insert(cap.capture());
        UsageEvent e = cap.getValue();
        assertThat(e.actor()).isEqualTo("alice");
        assertThat(e.role()).isEqualTo("admin");
        assertThat(e.action()).isEqualTo("admin.invite");
        assertThat(e.module()).isEqualTo("admin-ui");
        assertThat(e.ts()).isEqualTo(1717000000000L);
    }

    @Test
    void onUsageEvent_derivesModuleWhenMissing() {
        when(usage.insert(any())).thenReturn(Mono.empty());
        consumer.onUsageEvent(record("{\"actor\":\"bob\",\"role\":\"user\",\"action\":\"login\"}"));

        ArgumentCaptor<UsageEvent> cap = ArgumentCaptor.forClass(UsageEvent.class);
        verify(usage).insert(cap.capture());
        // login → login-ui per MODULE_OF; ts defaulted to now (>0).
        assertThat(cap.getValue().module()).isEqualTo("login-ui");
        assertThat(cap.getValue().ts()).isGreaterThan(0L);
    }

    @Test
    void onUsageEvent_dropsUnparseableRecordWithoutInsert() {
        consumer.onUsageEvent(record("not-json"));
        verify(usage, never()).insert(any());
    }

    @Test
    void onUsageEvent_rethrowsOnInsertFailure_soOffsetIsNotCommitted() {
        when(usage.insert(any())).thenReturn(Mono.error(new RuntimeException("clickhouse down")));
        try {
            consumer.onUsageEvent(record("{\"actor\":\"x\",\"action\":\"login\"}"));
            assertThat(false).as("expected the listener to rethrow").isTrue();
        } catch (RuntimeException expected) {
            assertThat(expected.getMessage()).contains("clickhouse down");
        }
    }
}
