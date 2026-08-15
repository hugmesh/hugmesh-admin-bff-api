package net.hugmesh.adminbff.desktop;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import net.hugmesh.adminbff.lease.AlwaysLeader;
import net.hugmesh.adminbff.lease.LeaderElection;
import net.hugmesh.authcore.provision.GatewayRevocationClient;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

/**
 * SHIPS-DARK proof for the desktop-sudo claim-sync lever — pins the
 * {@code @ConditionalOnProperty} wiring (NOT just the leaf classes), mirroring
 * {@link net.hugmesh.adminbff.cloudbackup.BackupStatusReconcilerWiringTest}. With NO
 * {@code app.desktop.sudo.claim-sync.enabled} property:
 * <ul>
 *   <li>the {@link DesktopSudoClaimSync} is the dark {@link NoopDesktopSudoClaimSync}
 *       (single-bean) — no Casdoor/gateway write ever happens on grant/revoke;</li>
 *   <li>NO {@link DesktopSudoClaimReconciler} bean exists — so no {@code @Scheduled}
 *       sweep runs. This is the load-bearing default-dark guarantee.</li>
 * </ul>
 * Flipping the flag true swaps in {@link CasdoorDesktopSudoClaimSync} AND registers the
 * reconciler — and does so even WITHOUT a {@link
 * net.hugmesh.authcore.casdoor.CasdoorAdminClient} bean (casdoor.admin disabled), in
 * which case the sync is a logged dry-run rather than a boot failure.
 */
class DesktopSudoClaimSyncWiringTest {

    /** The sync/reconciler collaborators (mocked repo, a DISABLED real revocation client —
     *  its enabled=false stub never dials) + the platform LeaderElection (the real
     *  AlwaysLeader, as in production single-replica). */
    @Configuration(proxyBeanMethods = false)
    static class TestDeps {
        @Bean
        DesktopSudoGrantRepository desktopSudoGrantRepository() {
            return mock(DesktopSudoGrantRepository.class);
        }
        @Bean
        GatewayRevocationClient gatewayRevocationClient() {
            return new GatewayRevocationClient(false, "http://gateway.invalid");
        }
        @Bean
        LeaderElection leaderElection() {
            return new AlwaysLeader();
        }
    }

    private final ApplicationContextRunner runner = new ApplicationContextRunner()
            .withUserConfiguration(TestDeps.class, DesktopSudoClaimSyncConfig.class);

    // ── DEFAULT (no property) -> dark: Noop sync, NO worker ──────────────────────

    @Test
    void claimSync_absentLever_shipsDark_noWorker() {
        runner.run(ctx -> {
            assertThat(ctx).hasSingleBean(DesktopSudoClaimSync.class);
            DesktopSudoClaimSync bean = ctx.getBean(DesktopSudoClaimSync.class);
            assertThat(bean).isInstanceOf(NoopDesktopSudoClaimSync.class);
            assertThat(bean.isReal()).isFalse();
            assertThat(ctx).doesNotHaveBean(DesktopSudoClaimReconciler.class);
        });
    }

    @Test
    void claimSync_leverExplicitlyFalse_staysDark() {
        runner.withPropertyValues("app.desktop.sudo.claim-sync.enabled=false").run(ctx -> {
            assertThat(ctx.getBean(DesktopSudoClaimSync.class))
                    .isInstanceOf(NoopDesktopSudoClaimSync.class);
            assertThat(ctx).doesNotHaveBean(DesktopSudoClaimReconciler.class);
        });
    }

    // ── lever on -> the REAL sync + the scheduled worker ─────────────────────────

    @Test
    void claimSync_leverOn_isCasdoorSync_withWorker() {
        runner.withPropertyValues("app.desktop.sudo.claim-sync.enabled=true").run(ctx -> {
            assertThat(ctx).hasSingleBean(DesktopSudoClaimSync.class);
            DesktopSudoClaimSync bean = ctx.getBean(DesktopSudoClaimSync.class);
            assertThat(bean).isInstanceOf(CasdoorDesktopSudoClaimSync.class);
            assertThat(bean.isReal()).isTrue();
            assertThat(ctx).hasSingleBean(DesktopSudoClaimReconciler.class);
        });
    }

    @Test
    void claimSync_leverOn_withoutCasdoorAdminClient_bootsAsDryRun() {
        // casdoor.admin.enabled=false -> NO CasdoorAdminClient bean anywhere; the lever-on
        // wiring must still boot (ObjectProvider -> null -> logged dry-run), never fail.
        runner.withPropertyValues("app.desktop.sudo.claim-sync.enabled=true").run(ctx -> {
            assertThat(ctx).hasNotFailed();
            assertThat(ctx.getBean(DesktopSudoClaimSync.class))
                    .isInstanceOf(CasdoorDesktopSudoClaimSync.class);
        });
    }
}
