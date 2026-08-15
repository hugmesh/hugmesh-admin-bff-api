package net.hugmesh.adminbff.egressvpn;

import io.fabric8.kubernetes.client.KubernetesClientBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Wires the REAL {@link Fabric8VpnConfigSecretWriter} — gated behind ONE flag,
 * {@code app.egress-vpn.secret-delivery.enabled} (DEFAULT false). Mirrors
 * {@code BackupEffectorConfig} EXACTLY (the {@code @ConditionalOnProperty} idiom + the lazy
 * fabric8 {@code KubernetesClient} supplier so a missing in-cluster context never fails BFF
 * boot).
 *
 * <h3>SHIPS DARK (the Noop stays the default)</h3>
 * With the flag OFF (the DEFAULT — every dev/test/CI run and every deployment until the
 * generator leg mounts {@code VPN_SECRET_DIR} on the nodes) this bean is NOT created and the
 * component-scanned {@link NoopVpnConfigSecretWriter} (gated on the SAME flag's {@code false}
 * branch) wins: imported config bytes are parse-validated then DROPPED, byte-identical to the
 * pre-delivery behaviour. {@code EgressVpnSecretDeliveryWiringTest} pins both directions AND
 * the shipped env-binding name.
 */
@Configuration(proxyBeanMethods = false)
public class EgressVpnSecretDeliveryConfig {

    private static final Logger log = LoggerFactory.getLogger(EgressVpnSecretDeliveryConfig.class);

    /** The REAL Secret writer — wired ONLY when the flag is true (mutually exclusive with the
     *  Noop, so exactly ONE {@link VpnConfigSecretWriter} exists in every mode). */
    @Bean
    @ConditionalOnProperty(name = "app.egress-vpn.secret-delivery.enabled", havingValue = "true")
    VpnConfigSecretWriter fabric8VpnConfigSecretWriter(
            @Value("${app.egress-vpn.secret-delivery.namespace:hugmesh-backend}") String namespace) {
        log.info("[egress-vpn] Secret delivery ENABLED (namespace={})", namespace);
        return new Fabric8VpnConfigSecretWriter(() -> new KubernetesClientBuilder().build(), namespace);
    }
}
