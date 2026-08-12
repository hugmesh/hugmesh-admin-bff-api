package net.hugmesh.adminbff.usage;

import org.apache.kafka.clients.consumer.ConsumerConfig;
import org.apache.kafka.clients.producer.ProducerConfig;
import org.apache.kafka.common.serialization.StringDeserializer;
import org.apache.kafka.common.serialization.StringSerializer;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.kafka.annotation.EnableKafka;
import org.springframework.kafka.config.ConcurrentKafkaListenerContainerFactory;
import org.springframework.kafka.core.ConsumerFactory;
import org.springframework.kafka.core.DefaultKafkaConsumerFactory;
import org.springframework.kafka.core.DefaultKafkaProducerFactory;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.kafka.core.ProducerFactory;

import java.util.HashMap;
import java.util.Map;

/**
 * Kafka usage-event bus wiring — String key (actor) + JSON String value, matching
 * the platform idiom. The WHOLE Kafka path is gated behind
 * {@code app.kafka.enabled} (default false) so a broker-less dev / test run boots
 * clean (no producer factory, no listener container, and the
 * {@code @Nullable KafkaTemplate} injected into {@link UsageService} resolves to
 * {@code null} ⇒ the service runs in its direct-write degraded mode).
 *
 * <p>Note on the WebFlux/native tension (documented as an open issue): the
 * spring-kafka {@code @KafkaListener} container is blocking and runs on its OWN
 * listener-container thread — it never touches the reactive request path. "Reactive
 * Kafka" here means the ClickHouse write inside the listener is a non-blocking
 * WebClient call, not reactor-kafka (the platform stays on spring-kafka).
 */
@Configuration
@EnableKafka
@ConditionalOnProperty(name = "app.kafka.enabled", havingValue = "true")
public class KafkaConfig {

    private final String bootstrapServers;
    private final String groupId;

    public KafkaConfig(
            @Value("${spring.kafka.bootstrap-servers:kafka:9092}") String bootstrapServers,
            @Value("${app.kafka.consumer.group-id:hugmesh-admin-bff-api-usage}") String groupId) {
        this.bootstrapServers = bootstrapServers;
        this.groupId = groupId;
    }

    @Bean
    public ProducerFactory<String, String> usageProducerFactory() {
        Map<String, Object> props = new HashMap<>();
        props.put(ProducerConfig.BOOTSTRAP_SERVERS_CONFIG, bootstrapServers);
        props.put(ProducerConfig.KEY_SERIALIZER_CLASS_CONFIG, StringSerializer.class);
        props.put(ProducerConfig.VALUE_SERIALIZER_CLASS_CONFIG, StringSerializer.class);
        return new DefaultKafkaProducerFactory<>(props);
    }

    @Bean
    public KafkaTemplate<String, String> kafkaTemplate(ProducerFactory<String, String> pf) {
        return new KafkaTemplate<>(pf);
    }

    @Bean
    public ConsumerFactory<String, String> usageConsumerFactory() {
        Map<String, Object> props = new HashMap<>();
        props.put(ConsumerConfig.BOOTSTRAP_SERVERS_CONFIG, bootstrapServers);
        props.put(ConsumerConfig.GROUP_ID_CONFIG, groupId);
        props.put(ConsumerConfig.KEY_DESERIALIZER_CLASS_CONFIG, StringDeserializer.class);
        props.put(ConsumerConfig.VALUE_DESERIALIZER_CLASS_CONFIG, StringDeserializer.class);
        props.put(ConsumerConfig.AUTO_OFFSET_RESET_CONFIG, "earliest");
        return new DefaultKafkaConsumerFactory<>(props);
    }

    @Bean
    public ConcurrentKafkaListenerContainerFactory<String, String> kafkaListenerContainerFactory(
            ConsumerFactory<String, String> cf) {
        ConcurrentKafkaListenerContainerFactory<String, String> factory =
                new ConcurrentKafkaListenerContainerFactory<>();
        factory.setConsumerFactory(cf);
        return factory;
    }
}
