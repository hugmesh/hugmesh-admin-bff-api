package net.hugmesh.adminbff.desktop;

import org.junit.jupiter.api.Test;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import net.hugmesh.adminbff.lease.AlwaysLeader;
import net.hugmesh.adminbff.lease.LeaderElection;
import net.hugmesh.adminbff.SubjectRevocationTtl;
import net.hugmesh.authcore.casdoor.CasdoorAdminClient;
import net.hugmesh.authcore.provision.GatewayRevocationClient;

import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

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

    /** A mocked Casdoor admin client and gateway client, so the TTLs the bean was built with
     *  are visible on the calls it makes. */
    @Configuration(proxyBeanMethods = false)
    static class RecordingDeps {
        @Bean
        DesktopSudoGrantRepository desktopSudoGrantRepository() {
            DesktopSudoGrantRepository repo = mock(DesktopSudoGrantRepository.class);
            when(repo.hasActiveForSubject(anyString())).thenReturn(Mono.just(false));
            return repo;
        }
        @Bean
        GatewayRevocationClient gatewayRevocationClient() {
            GatewayRevocationClient client = mock(GatewayRevocationClient.class);
            when(client.revokeSubject(anyString(), anyString(), anyLong())).thenReturn(Mono.empty());
            return client;
        }
        @Bean
        CasdoorAdminClient casdoorAdminClient() {
            CasdoorAdminClient casdoor = mock(CasdoorAdminClient.class);
            when(casdoor.organization()).thenReturn("hugmesh");
            when(casdoor.addUserToRole(anyString(), anyString())).thenReturn(Mono.empty());
            when(casdoor.removeUserFromRole(anyString(), anyString())).thenReturn(Mono.empty());
            return casdoor;
        }
        @Bean
        LeaderElection leaderElection() {
            return new AlwaysLeader();
        }
    }

    private static DesktopSudoGrant grant(String state) {
        return new DesktopSudoGrant("g-1", "alice", "dev-1", state, "root", Instant.now(),
                null, null, "brandx", DesktopSudoGrant.PROP_PENDING, 1L);
    }

    @Test
    void claimSync_leverOn_bindsTheCutOffTtlToRevokeAndTheGrantTtlToGrant() {
        // Values unlike either default and unlike each other: the bean must take each one from
        // its own property (a broken placeholder would fall back to the default) and hand it to
        // the right call (swapping the two parameters would put 168 h on a grant and 1 h on a
        // revoke, the defect this TTL split exists to prevent).
        new ApplicationContextRunner()
                .withUserConfiguration(RecordingDeps.class, DesktopSudoClaimSyncConfig.class)
                .withPropertyValues("app.desktop.sudo.claim-sync.enabled=true",
                        SubjectRevocationTtl.CUTOFF_PROPERTY + "=777001",
                        SubjectRevocationTtl.GRANT_PROPERTY + "=1201")
                .run(ctx -> {
                    DesktopSudoClaimSync sync = ctx.getBean(DesktopSudoClaimSync.class);
                    GatewayRevocationClient revocations = ctx.getBean(GatewayRevocationClient.class);

                    StepVerifier.create(sync.propagate(grant(DesktopSudoGrant.STATE_ACTIVE)))
                            .expectNext(DesktopSudoGrant.PROP_APPLIED).verifyComplete();
                    verify(revocations).revokeSubject("alice", "desktop-sudo-grant", 1201L);

                    StepVerifier.create(sync.propagate(grant(DesktopSudoGrant.STATE_REVOKED)))
                            .expectNext(DesktopSudoGrant.PROP_APPLIED).verifyComplete();
                    verify(revocations).revokeSubject("alice", "desktop-sudo-revoke", 777001L);
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
