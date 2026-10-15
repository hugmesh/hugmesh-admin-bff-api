package net.hugmesh.adminbff.usage;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import org.apache.kafka.clients.consumer.ConsumerRecord;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.kafka.annotation.KafkaListener;
import org.springframework.stereotype.Component;

/**
 * The @KafkaListener usage consumer — makes Kafka the durable usage bus. Consumes
 * JSON usage events from {@code app.kafka.topic.usage-events} (produced by the UIs
 * / gateways / services AND by this BFF's own {@link UsageService#record}) and
 * persists each to {@code hugmesh.usage_events} in ClickHouse via the
 * non-blocking WebClient on {@link UsageService#insert}.
 *
 * <p>Gated behind {@code app.kafka.enabled} (same flag as {@link KafkaConfig}) so
 * a broker-less dev / test run does not register the listener container.
 *
 * <p>The listener runs on its own spring-kafka container thread (blocking by
 * nature); the ClickHouse write it triggers is reactive (WebClient). We
 * {@code block()} on that write here so an offset is only committed after a
 * successful persist — at-least-once delivery — but on the container thread, never
 * the WebFlux event loop.
 */
@Component
@ConditionalOnProperty(name = "app.kafka.enabled", havingValue = "true")
@SuppressFBWarnings(value = "EI_EXPOSE_REP2",
        justification = "Spring constructor injection: the container owns this singleton collaborator and it is never mutated by this class after construction; a defensive copy of a bean is meaningless (not caller-owned mutable data).")
public class UsageEventConsumer {

    private static final Logger log = LoggerFactory.getLogger(UsageEventConsumer.class);

    private final UsageService usage;
    private final ObjectMapper json = new ObjectMapper();

    public UsageEventConsumer(UsageService usage) {
        this.usage = usage;
    }

    @KafkaListener(
            topics = "${app.kafka.topic.usage-events:usage_events}",
            groupId = "${app.kafka.consumer.group-id:hugmesh-admin-bff-api-usage}")
    public void onUsageEvent(ConsumerRecord<String, String> record) {
        UsageEvent event = parse(record.value());
        if (event == null) return;
        try {
            // Block on the reactive ClickHouse write on this container thread so the
            // offset is committed only after a successful persist (at-least-once).
            usage.insert(event).block();
        } catch (Exception e) {
            // Re-throw so spring-kafka does not commit the offset and redelivers.
            log.warn("[usage-consumer] clickhouse insert failed, will redeliver: {}", e.toString());
            throw e;
        }
    }

    /** Parse the usage-event JSON into a {@link UsageEvent}; null + log on garbage. */
    UsageEvent parse(String value) {
        if (value == null || value.isBlank()) return null;
        try {
            JsonNode n = json.readTree(value);
            String actor = n.path("actor").asText("");
            String action = n.path("action").asText("");
            String role = n.path("role").asText("user");
            String module = n.hasNonNull("module")
                    ? n.path("module").asText()
                    : UsageService.moduleOf(action);
            long ts = n.hasNonNull("ts") ? n.path("ts").asLong() : System.currentTimeMillis();
            return new UsageEvent(actor, role, action, module, ts);
        } catch (Exception e) {
            log.warn("[usage-consumer] dropping unparseable usage event: {}", e.toString());
            return null;
        }
    }
}
