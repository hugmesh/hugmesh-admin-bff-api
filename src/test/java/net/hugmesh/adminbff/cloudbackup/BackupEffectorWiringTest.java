package net.hugmesh.adminbff.cloudbackup;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

/**
 * SHIPS-DARK proof for the Velero effector leg — pins the {@code @ConditionalOnProperty}
 * wiring (NOT just the leaf classes). With NO {@code app.backups.effector.enabled} property the
 * injected {@link BackupEffector} + {@link RunningServiceProvider} are the foundation's dark
 * defaults ({@link NoopBackupEffector} / {@link StubRunningServiceProvider}) — single-bean, so
 * a created backup_set emits NO Velero CR and reads NO cluster ConfigMap. Flipping the flag true
 * swaps in {@link VeleroBackupEffector} + {@link ConfigMapRunningServiceProvider} (still
 * single-bean). This is the load-bearing guarantee that the feature dials no cluster by default.
 */
class BackupEffectorWiringTest {

    /** A mock {@link BackupSetRepository} (the real Velero effector bean's dependency). The
     *  foundation's dark defaults are registered as their REAL {@code @Component} classes (not
     *  hand-built beans) so their flag/missing-bean backoff conditions are evaluated exactly as
     *  in production. */
    @Configuration(proxyBeanMethods = false)
    static class TestDeps {
        @Bean
        BackupSetRepository backupSetRepository() {
            return mock(BackupSetRepository.class);
        }
    }

    private final ApplicationContextRunner runner = new ApplicationContextRunner()
            .withUserConfiguration(TestDeps.class, NoopBackupEffector.class,
                    StubRunningServiceProvider.class, BackupEffectorConfig.class);

    // ── DEFAULT (no property) -> the dark Noop / Stub ────────────────────────────────────

    @Test
    void effector_defaultsToNoop_shipsDark() {
        runner.run(ctx -> {
            assertThat(ctx).hasSingleBean(BackupEffector.class);
            assertThat(ctx.getBean(BackupEffector.class)).isInstanceOf(NoopBackupEffector.class);
            // no Velero CR factory / real effector wired at all.
            assertThat(ctx).doesNotHaveBean(VeleroResourceFactory.class);
            assertThat(ctx).doesNotHaveBean(VeleroBackupEffector.class);
        });
    }

    @Test
    void runningServiceProvider_defaultsToStub_shipsDark() {
        runner.run(ctx -> {
            assertThat(ctx).hasSingleBean(RunningServiceProvider.class);
            assertThat(ctx.getBean(RunningServiceProvider.class))
                    .isInstanceOf(StubRunningServiceProvider.class);
            assertThat(ctx).doesNotHaveBean(ConfigMapRunningServiceProvider.class);
        });
    }

    @Test
    void effectorExplicitlyFalse_staysNoop() {
        runner.withPropertyValues("app.backups.effector.enabled=false").run(ctx -> {
            assertThat(ctx).hasSingleBean(BackupEffector.class);
            assertThat(ctx.getBean(BackupEffector.class)).isInstanceOf(NoopBackupEffector.class);
        });
    }

    // ── enabled=true -> the REAL Velero effector + ConfigMap provider ────────────────────

    @Test
    void effector_whenEnabled_isVelero_andSingleBean() {
        runner.withPropertyValues("app.backups.effector.enabled=true").run(ctx -> {
            assertThat(ctx).hasSingleBean(BackupEffector.class);
            assertThat(ctx.getBean(BackupEffector.class)).isInstanceOf(VeleroBackupEffector.class);
            assertThat(ctx).hasSingleBean(VeleroResourceFactory.class);
        });
    }

    @Test
    void runningServiceProvider_whenEnabled_isConfigMapBacked_andSingleBean() {
        runner.withPropertyValues("app.backups.effector.enabled=true").run(ctx -> {
            assertThat(ctx).hasSingleBean(RunningServiceProvider.class);
            assertThat(ctx.getBean(RunningServiceProvider.class))
                    .isInstanceOf(ConfigMapRunningServiceProvider.class);
        });
    }
}
