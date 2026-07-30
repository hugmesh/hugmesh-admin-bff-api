package systems.hugmesh.adminbff.backingservices;

import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Wires the {@link BackingServiceEffector} seam the {@link BackingServiceModeReconciler} uses.
 * The v1 default is the dark {@link NoopBackingServiceEffector}, registered
 * {@code @ConditionalOnMissingBean} so a follow-on leg's REAL effector (defined in its own
 * source) deterministically wins when present — the design's "Noop @ConditionalOnMissingBean"
 * posture. No cluster is ever dialed at defaults.
 */
@Configuration(proxyBeanMethods = false)
public class BackingServiceEffectorConfig {

    @Bean
    @ConditionalOnMissingBean
    BackingServiceEffector noopBackingServiceEffector() {
        return new NoopBackingServiceEffector();
    }
}
