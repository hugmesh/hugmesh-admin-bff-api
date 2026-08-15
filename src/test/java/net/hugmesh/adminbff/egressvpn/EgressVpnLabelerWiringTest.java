package net.hugmesh.adminbff.egressvpn;

import org.junit.jupiter.api.Test;
import org.springframework.boot.env.YamlPropertySourceLoader;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.PropertySource;
import org.springframework.core.io.ClassPathResource;
import net.hugmesh.adminbff.lease.AlwaysLeader;
import net.hugmesh.adminbff.lease.LeaderElection;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

/**
 * SHIPS-DARK proof for the egress-VPN pod-labeling leg — pins the
 * {@code @ConditionalOnProperty} wiring (NOT just the leaf classes), mirroring
 * {@link net.hugmesh.adminbff.cloudbackup.BackupStatusReconcilerWiringTest}. With NO
 * {@code app.egress-vpn.labeler.enabled} property:
 * <ul>
 *   <li>the {@link VpnEgressLabeler} is the dark {@link NoopVpnEgressLabeler} (single-bean) —
 *       no workload/pod is ever labelled, the interaction NetworkPolicy stays inert;</li>
 *   <li>NO {@link VpnEgressLabelReconciler} bean exists — so no {@code @Scheduled} sweep runs
 *       and no cluster is dialed. This is the load-bearing default-dark guarantee.</li>
 * </ul>
 * Flipping the flag true swaps in {@link Fabric8VpnEgressLabeler} AND registers the sweep.
 *
 * <p>Also pins the SHIPPED {@code application.yml} env bindings (the deployment contract):
 * {@code EGRESS_VPN_LABELER_ENABLED} MUST default false, and the namespace / slug-set /
 * cadence bindings carry the documented names.
 */
class EgressVpnLabelerWiringTest {

    /** The labeler bean's collaborators (mocked repo) + the platform LeaderElection (the real
     *  AlwaysLeader, as in production single-replica). */
    @Configuration(proxyBeanMethods = false)
    static class TestDeps {
        @Bean
        VpnNodeAssignmentRepository vpnNodeAssignmentRepository() {
            return mock(VpnNodeAssignmentRepository.class);
        }
        @Bean
        LeaderElection leaderElection() {
            return new AlwaysLeader();
        }
    }

    private final ApplicationContextRunner runner = new ApplicationContextRunner()
            .withUserConfiguration(TestDeps.class, NoopVpnEgressLabeler.class,
                    EgressVpnLabelerConfig.class);

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
        Object raw = shippedValue("app.egress-vpn.labeler.enabled");
        assertThat(raw).as("shipped app.egress-vpn.labeler.enabled").isNotNull();
        assertThat(raw.toString()).isEqualTo("${EGRESS_VPN_LABELER_ENABLED:false}");
    }

    @Test
    void shippedTuningBindings_carryTheContractEnvNames() throws Exception {
        assertThat(shippedValue("app.egress-vpn.labeler.namespace").toString())
                .isEqualTo("${EGRESS_VPN_LABELER_NAMESPACE:hugmesh-backend}");
        assertThat(shippedValue("app.egress-vpn.labeler.domain-service-slugs").toString())
                .isEqualTo("${EGRESS_VPN_LABELER_DOMAIN_SERVICE_SLUGS:akkoma,tuwunel,coturn}");
        assertThat(shippedValue("app.egress-vpn.labeler.interval-ms").toString())
                .isEqualTo("${EGRESS_VPN_LABELER_INTERVAL_MS:30000}");
        assertThat(shippedValue("app.egress-vpn.labeler.initial-delay-ms").toString())
                .isEqualTo("${EGRESS_VPN_LABELER_INITIAL_DELAY_MS:25000}");
    }

    // ── DEFAULT (no property) -> dark: Noop labeler, NO reconciler ────────────────────────

    @Test
    void labeler_defaultsToNoop_andNoSweep_shipsDark() {
        runner.run(ctx -> {
            assertThat(ctx).hasSingleBean(VpnEgressLabeler.class);
            VpnEgressLabeler bean = ctx.getBean(VpnEgressLabeler.class);
            assertThat(bean).isInstanceOf(NoopVpnEgressLabeler.class);
            assertThat(bean.isReal()).isFalse();
            assertThat(ctx).doesNotHaveBean(Fabric8VpnEgressLabeler.class);
            assertThat(ctx).doesNotHaveBean(VpnEgressLabelReconciler.class);
        });
    }

    @Test
    void labeler_explicitlyFalse_staysDark() {
        runner.withPropertyValues("app.egress-vpn.labeler.enabled=false").run(ctx -> {
            assertThat(ctx.getBean(VpnEgressLabeler.class))
                    .isInstanceOf(NoopVpnEgressLabeler.class);
            assertThat(ctx).doesNotHaveBean(VpnEgressLabelReconciler.class);
        });
    }

    // ── enabled=true -> the REAL fabric8 labeler + the sweep ──────────────────────────────

    @Test
    void labeler_whenEnabled_isFabric8_withSweep_andSingleBean() {
        runner.withPropertyValues("app.egress-vpn.labeler.enabled=true").run(ctx -> {
            assertThat(ctx).hasSingleBean(VpnEgressLabeler.class);
            VpnEgressLabeler bean = ctx.getBean(VpnEgressLabeler.class);
            assertThat(bean).isInstanceOf(Fabric8VpnEgressLabeler.class);
            assertThat(bean.isReal()).isTrue();
            assertThat(ctx).hasSingleBean(VpnEgressLabelReconciler.class);
            assertThat(ctx).doesNotHaveBean(NoopVpnEgressLabeler.class);
        });
    }
}
