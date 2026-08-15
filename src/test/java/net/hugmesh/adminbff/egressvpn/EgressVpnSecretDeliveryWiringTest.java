package net.hugmesh.adminbff.egressvpn;

import org.junit.jupiter.api.Test;
import org.springframework.boot.env.YamlPropertySourceLoader;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.core.env.PropertySource;
import org.springframework.core.io.ClassPathResource;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * SHIPS-DARK proof for the egress-VPN Secret-delivery leg — pins the
 * {@code @ConditionalOnProperty} wiring (NOT just the leaf classes), mirroring
 * {@link net.hugmesh.adminbff.cloudbackup.BackupEffectorWiringTest}. With NO
 * {@code app.egress-vpn.secret-delivery.enabled} property the injected
 * {@link VpnConfigSecretWriter} is the dark {@link NoopVpnConfigSecretWriter} (single-bean) —
 * an imported config's bytes are parse-validated then DROPPED and no cluster is dialed.
 * Flipping the flag true swaps in {@link Fabric8VpnConfigSecretWriter} (still single-bean).
 *
 * <p>Also pins the SHIPPED {@code application.yml} binding (the
 * {@code ${ENV_NAME:default}} shape) so the deployment lever's env names are load-bearing
 * contract, exactly as {@code PlatformCapabilitiesWiringTest} pins its probe default:
 * {@code EGRESS_VPN_SECRET_DELIVERY_ENABLED} MUST default false (dark) and
 * {@code EGRESS_VPN_SECRET_NAMESPACE} MUST default the backend namespace the generator
 * manifests deploy into.
 */
class EgressVpnSecretDeliveryWiringTest {

    private final ApplicationContextRunner runner = new ApplicationContextRunner()
            .withUserConfiguration(NoopVpnConfigSecretWriter.class, EgressVpnSecretDeliveryConfig.class);

    // ── shipped application.yml env bindings (the deployment contract) ────────────────────

    private static Object shippedValue(String key) throws Exception {
        List<PropertySource<?>> sources = new YamlPropertySourceLoader()
                .load("application.yml", new ClassPathResource("application.yml"));
        for (PropertySource<?> ps : sources) {
            Object v = ps.getProperty(key);
            if (v != null) return v;
        }
        return null;
    }

    @Test
    void shippedEnabledBinding_isTheContractEnvName_andDefaultsFalse() throws Exception {
        Object raw = shippedValue("app.egress-vpn.secret-delivery.enabled");
        assertThat(raw).as("shipped app.egress-vpn.secret-delivery.enabled").isNotNull();
        assertThat(raw.toString()).isEqualTo("${EGRESS_VPN_SECRET_DELIVERY_ENABLED:false}");
    }

    @Test
    void shippedNamespaceBinding_isTheContractEnvName_andDefaultsBackendNamespace() throws Exception {
        Object raw = shippedValue("app.egress-vpn.secret-delivery.namespace");
        assertThat(raw).as("shipped app.egress-vpn.secret-delivery.namespace").isNotNull();
        assertThat(raw.toString()).isEqualTo("${EGRESS_VPN_SECRET_NAMESPACE:hugmesh-backend}");
    }

    // ── DEFAULT (no property) -> the dark Noop ────────────────────────────────────────────

    @Test
    void writer_defaultsToNoop_shipsDark() {
        runner.run(ctx -> {
            assertThat(ctx).hasSingleBean(VpnConfigSecretWriter.class);
            VpnConfigSecretWriter bean = ctx.getBean(VpnConfigSecretWriter.class);
            assertThat(bean).isInstanceOf(NoopVpnConfigSecretWriter.class);
            assertThat(bean.isReal()).isFalse();
            assertThat(ctx).doesNotHaveBean(Fabric8VpnConfigSecretWriter.class);
        });
    }

    @Test
    void writer_explicitlyFalse_staysNoop() {
        runner.withPropertyValues("app.egress-vpn.secret-delivery.enabled=false").run(ctx -> {
            assertThat(ctx).hasSingleBean(VpnConfigSecretWriter.class);
            assertThat(ctx.getBean(VpnConfigSecretWriter.class))
                    .isInstanceOf(NoopVpnConfigSecretWriter.class);
        });
    }

    // ── enabled=true -> the REAL fabric8 writer ───────────────────────────────────────────

    @Test
    void writer_whenEnabled_isFabric8_andSingleBean() {
        runner.withPropertyValues("app.egress-vpn.secret-delivery.enabled=true").run(ctx -> {
            assertThat(ctx).hasSingleBean(VpnConfigSecretWriter.class);
            VpnConfigSecretWriter bean = ctx.getBean(VpnConfigSecretWriter.class);
            assertThat(bean).isInstanceOf(Fabric8VpnConfigSecretWriter.class);
            assertThat(bean.isReal()).isTrue();
            assertThat(ctx).doesNotHaveBean(NoopVpnConfigSecretWriter.class);
        });
    }
}
