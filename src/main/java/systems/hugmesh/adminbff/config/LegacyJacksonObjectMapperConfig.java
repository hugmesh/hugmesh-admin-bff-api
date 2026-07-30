package systems.hugmesh.adminbff.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.jackson.autoconfigure.JsonMapperBuilderCustomizer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import tools.jackson.databind.DeserializationFeature;

/**
 * Boot 4 / Jackson 3 bridge.
 *
 * <p>Spring Boot 4 promoted Jackson 3 ({@code tools.jackson.databind.ObjectMapper})
 * to the auto-configured JSON mapper, so the framework no longer registers a
 * {@code com.fasterxml.jackson.databind.ObjectMapper} (Jackson 2) bean. Several BFF
 * components inject the Jackson-2 {@link ObjectMapper} directly to parse opaque
 * upstream JSON that is NOT part of the HTTP request/response codec path — the
 * Headscale node list ({@code HeadscaleNodesClient}), the workload-console exec
 * frames ({@code WorkloadExecWebSocketHandler} / {@code WorkloadConsoleClientConfig})
 * and the device SSH-terminal frames ({@code DeviceSshTerminalWebSocketHandler} /
 * {@code DeviceTerminalConfig}). These use only the portable {@code readTree} /
 * {@code JsonNode} / {@code createArrayNode} surface.
 *
 * <p>Rather than churn ~6 call sites onto the slightly different Jackson-3 API (and
 * its unchecked-exception signature change), this restores the single Jackson-2
 * {@link ObjectMapper} bean those injections expect. The reactive WebFlux JSON
 * codecs continue to use Boot 4's auto-configured Jackson-3 mapper untouched — this
 * bean is independent of the request/response serialization path. Guarded by
 * {@link ConditionalOnMissingBean} so it never shadows an explicit override.
 */
@Configuration(proxyBeanMethods = false)
public class LegacyJacksonObjectMapperConfig {

    @Bean
    @ConditionalOnMissingBean(ObjectMapper.class)
    ObjectMapper jackson2ObjectMapper() {
        return new ObjectMapper();
    }

    /**
     * Jackson 3 (Boot 4) FLIPPED {@link DeserializationFeature#FAIL_ON_NULL_FOR_PRIMITIVES}
     * to ON by default (it was OFF in Jackson 2 / Boot 3.5). That makes a JSON body which
     * OMITS a primitive-typed field of a {@code record} DTO fail to deserialize with a
     * {@code DecodingException} ("Cannot map `null` into type `int`") BEFORE bean validation
     * even runs — e.g. a partial test-runner ingest event ({@code TestRunIngestRequest} with
     * {@code int passed/failed/skipped/percent} omitted) that the Boot 3.5 contract accepted
     * as zeros. Restore the lenient default so omitted numeric fields coerce to their zero
     * default exactly as before, on the auto-configured Jackson-3 WebFlux JSON codec mapper.
     */
    @Bean
    JsonMapperBuilderCustomizer lenientMissingPrimitivesCustomizer() {
        return builder -> builder.disable(DeserializationFeature.FAIL_ON_NULL_FOR_PRIMITIVES);
    }
}
