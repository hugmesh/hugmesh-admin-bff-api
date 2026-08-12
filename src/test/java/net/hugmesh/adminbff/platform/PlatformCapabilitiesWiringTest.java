package net.hugmesh.adminbff.platform;

import org.junit.jupiter.api.Test;
import org.springframework.boot.env.YamlPropertySourceLoader;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.core.env.PropertySource;
import org.springframework.core.io.ClassPathResource;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Pins the {@code @ConditionalOnProperty} wiring of the {@link PlatformCapabilityProbe} AND the
 * shipped {@code application.yml} DEFAULT for {@code app.platform-capabilities.k8s.enabled}.
 *
 * <p>The blocker this guards: with the probe disabled the {@link NoopPlatformCapabilityProbe}
 * reports ArgoCD / Velero / build-node ABSENT on a working cluster, which over-degrades the UI.
 * The fix flips the shipped DEFAULT to {@code true} so the read-only, fail-safe
 * {@link Fabric8PlatformCapabilityProbe} (which RBAC-denies / errors / no-clients all degrade to
 * absent + warning, never a 500 or a faked true) does ACCURATE detection by default. The property
 * is kept so an operator can still disable it — both directions are pinned below.
 */
class PlatformCapabilitiesWiringTest {

    private final ApplicationContextRunner runner = new ApplicationContextRunner()
            .withUserConfiguration(PlatformCapabilitiesConfig.class);

    // ── shipped application.yml DEFAULT ──────────────────────────────────────────────────────

    @Test
    void shippedDefault_enablesTheRealProbe() throws Exception {
        // Load the value exactly as it ships in application.yml (the ${...:default} fallback).
        List<PropertySource<?>> sources = new YamlPropertySourceLoader()
                .load("application.yml", new ClassPathResource("application.yml"));
        Object raw = null;
        for (PropertySource<?> ps : sources) {
            Object v = ps.getProperty("app.platform-capabilities.k8s.enabled");
            if (v != null) {
                raw = v;
                break;
            }
        }
        assertThat(raw).as("shipped app.platform-capabilities.k8s.enabled default")
                .isNotNull();
        // The shipped value is "${PLATFORM_CAPABILITIES_K8S_ENABLED:true}" — the fallback is true,
        // so accurate detection (the real probe) is the default when the env var is unset.
        assertThat(raw.toString()).contains(":true").doesNotContain(":false");
    }

    // ── DEFAULT (enabled=true, the shipped value) -> the REAL fabric8 probe ───────────────────

    @Test
    void whenEnabledTrue_isFabric8Probe_real() {
        runner.withPropertyValues("app.platform-capabilities.k8s.enabled=true").run(ctx -> {
            assertThat(ctx).hasSingleBean(PlatformCapabilityProbe.class);
            PlatformCapabilityProbe bean = ctx.getBean(PlatformCapabilityProbe.class);
            assertThat(bean).isInstanceOf(Fabric8PlatformCapabilityProbe.class);
            assertThat(bean.isReal()).isTrue();
        });
    }

    // ── operator opt-out (enabled=false) -> the Noop ─────────────────────────────────────────

    @Test
    void whenDisabled_isNoopProbe_notReal() {
        runner.withPropertyValues("app.platform-capabilities.k8s.enabled=false").run(ctx -> {
            assertThat(ctx).hasSingleBean(PlatformCapabilityProbe.class);
            PlatformCapabilityProbe bean = ctx.getBean(PlatformCapabilityProbe.class);
            assertThat(bean).isInstanceOf(NoopPlatformCapabilityProbe.class);
            assertThat(bean.isReal()).isFalse();
        });
    }
}
