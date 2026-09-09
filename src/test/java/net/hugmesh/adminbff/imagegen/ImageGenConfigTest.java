package net.hugmesh.adminbff.imagegen;

import io.fabric8.kubernetes.client.KubernetesClientException;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import net.hugmesh.commons.web.ApiException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Pins the SHIPS-DARK wiring of the image-gen launcher seam with an {@link ApplicationContextRunner}:
 * <ul>
 *   <li><b>default (no property)</b> → exactly ONE {@link ImageJobLauncher}, the
 *       {@link NoopImageJobLauncher} ({@code isReal()==false}) — the orchestrator launches
 *       NOTHING for real;</li>
 *   <li><b>imagegen.launch.enabled=false</b> → same (explicit dark);</li>
 *   <li><b>imagegen.launch.enabled=true</b> → exactly ONE launcher, the REAL
 *       {@link Fabric8ImageJobLauncher} ({@code isReal()==true}) — and crucially NOT both
 *       (the NoUniqueBeanDefinitionException the mutually-exclusive gating prevents).</li>
 * </ul>
 * Plus the launcher seam's error contract (cluster rejection → 502, never a raw 500).
 */
class ImageGenConfigTest {

    private final ApplicationContextRunner runner = new ApplicationContextRunner()
            .withUserConfiguration(ImageGenConfig.class);

    @Test
    void default_isDarkNoopOnly() {
        runner.run(ctx -> {
            assertThat(ctx).hasSingleBean(ImageJobLauncher.class);
            assertThat(ctx.getBean(ImageJobLauncher.class)).isInstanceOf(NoopImageJobLauncher.class);
            assertThat(ctx.getBean(ImageJobLauncher.class).isReal()).isFalse();
        });
    }

    @Test
    void explicitFalse_isDarkNoopOnly() {
        runner.withPropertyValues("imagegen.launch.enabled=false").run(ctx -> {
            assertThat(ctx).hasSingleBean(ImageJobLauncher.class);
            assertThat(ctx.getBean(ImageJobLauncher.class)).isInstanceOf(NoopImageJobLauncher.class);
        });
    }

    @Test
    void enabledTrue_isRealFabric8Only_notBoth() {
        runner.withPropertyValues("imagegen.launch.enabled=true").run(ctx -> {
            assertThat(ctx).hasNotFailed();
            assertThat(ctx).hasSingleBean(ImageJobLauncher.class);   // EXACTLY ONE — not both
            assertThat(ctx.getBean(ImageJobLauncher.class)).isInstanceOf(Fabric8ImageJobLauncher.class);
            assertThat(ctx.getBean(ImageJobLauncher.class).isReal()).isTrue();
        });
    }

    @Test
    void noopLauncher_isNotReal_andReturnsSyntheticName() {
        ImageJobLauncher launcher = new NoopImageJobLauncher();
        assertThat(launcher.isReal()).isFalse();
        assertThat(launcher.apply("apiVersion: batch/v1\nkind: Job\n", "b-9").block())
                .isEqualTo("hugmesh-image-gen-b-9");
    }

    @Test
    void fabric8Launcher_clusterRejection_mapsToBadGateway() {
        Fabric8ImageJobLauncher launcher = new Fabric8ImageJobLauncher(
                () -> { throw new KubernetesClientException("forbidden: jobs is forbidden"); },
                "hugmesh-backend");
        assertThat(launcher.isReal()).isTrue();
        assertThatThrownBy(() -> launcher.apply("kind: Job\n", "b-1").block())
                .isInstanceOf(ApiException.class)
                .satisfies(e -> assertThat(((ApiException) e).status().value()).isEqualTo(502))
                .hasMessageContaining("could not launch image-gen Job");
    }
}
