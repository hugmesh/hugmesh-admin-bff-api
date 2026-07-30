package systems.hugmesh.adminbff.cloudbackup;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import systems.hugmesh.adminbff.lease.AlwaysLeader;
import systems.hugmesh.adminbff.lease.LeaderElection;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

/**
 * SHIPS-DARK proof for the catalog-write status reconciler — pins the
 * {@code @ConditionalOnProperty} wiring (NOT just the leaf classes), mirroring
 * {@link BackupEffectorWiringTest}. With NO {@code app.backups.effector.enabled} property:
 * <ul>
 *   <li>the {@link VeleroStatusReader} is the dark {@link NoopVeleroStatusReader} (single-bean) —
 *       no fabric8 reader, so nothing lists Velero CRs;</li>
 *   <li>NO {@link BackupStatusReconciler} bean exists — so no {@code @Scheduled} sweep runs and no
 *       cluster is dialed. This is the load-bearing default-dark guarantee.</li>
 * </ul>
 * Flipping the flag true swaps in {@link Fabric8VeleroStatusReader} AND registers the
 * {@link BackupStatusReconciler}.
 */
class BackupStatusReconcilerWiringTest {

    /** The reconciler bean's collaborators (mocked) + the platform LeaderElection (the real
     *  AlwaysLeader, as in production single-replica). */
    @Configuration(proxyBeanMethods = false)
    static class TestDeps {
        @Bean
        BackupSetRepository backupSetRepository() {
            return mock(BackupSetRepository.class);
        }
        @Bean
        LeaderElection leaderElection() {
            return new AlwaysLeader();
        }
    }

    private final ApplicationContextRunner runner = new ApplicationContextRunner()
            .withUserConfiguration(TestDeps.class, BackupStatusReconcilerConfig.class);

    // ── DEFAULT (no property) -> dark: noop reader, NO reconciler ──────────────────────────

    @Test
    void reconciler_absentByDefault_shipsDark() {
        runner.run(ctx -> {
            assertThat(ctx).doesNotHaveBean(BackupStatusReconciler.class);
            assertThat(ctx).doesNotHaveBean(Fabric8VeleroStatusReader.class);
            assertThat(ctx).hasSingleBean(VeleroStatusReader.class);
            assertThat(ctx.getBean(VeleroStatusReader.class))
                    .isInstanceOf(NoopVeleroStatusReader.class);
        });
    }

    @Test
    void reconciler_explicitlyFalse_staysDark() {
        runner.withPropertyValues("app.backups.effector.enabled=false").run(ctx -> {
            assertThat(ctx).doesNotHaveBean(BackupStatusReconciler.class);
            assertThat(ctx.getBean(VeleroStatusReader.class))
                    .isInstanceOf(NoopVeleroStatusReader.class);
        });
    }

    // ── enabled=true -> the reconciler + the fabric8 reader ────────────────────────────────

    @Test
    void reconciler_whenEnabled_isRegistered_withFabric8Reader() {
        runner.withPropertyValues("app.backups.effector.enabled=true").run(ctx -> {
            assertThat(ctx).hasSingleBean(BackupStatusReconciler.class);
            assertThat(ctx).hasSingleBean(VeleroStatusReader.class);
            assertThat(ctx.getBean(VeleroStatusReader.class))
                    .isInstanceOf(Fabric8VeleroStatusReader.class);
            assertThat(ctx).doesNotHaveBean(NoopVeleroStatusReader.class);
        });
    }
}
