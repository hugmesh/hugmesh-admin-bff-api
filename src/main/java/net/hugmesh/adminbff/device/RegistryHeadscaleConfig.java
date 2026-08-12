package net.hugmesh.adminbff.device;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Wires the HEADSCALE-ANCHORED machine_key_fp AUTO-CAPTURE collaborators: binds
 * {@link RegistryHeadscaleProperties} ({@code app.registry.headscale.*}) and provides the
 * {@link HeadscaleNodesClient} bean. {@link ConditionalOnMissingBean} lets a test inject a
 * mock client without this real one fighting it. The same config-only seam pattern as
 * {@code WorkloadConsoleClientConfig}.
 */
@Configuration(proxyBeanMethods = false)
@EnableConfigurationProperties(RegistryHeadscaleProperties.class)
public class RegistryHeadscaleConfig {

    @Bean
    @ConditionalOnMissingBean(HeadscaleNodesClient.class)
    HeadscaleNodesClient headscaleNodesClient(RegistryHeadscaleProperties props, ObjectMapper mapper) {
        return new HeadscaleNodesClient(props, mapper);
    }
}
