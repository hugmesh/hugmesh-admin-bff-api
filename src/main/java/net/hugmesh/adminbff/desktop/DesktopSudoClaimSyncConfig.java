package net.hugmesh.adminbff.desktop;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import net.hugmesh.adminbff.lease.LeaderElection;
import net.hugmesh.authcore.casdoor.CasdoorAdminClient;
import net.hugmesh.authcore.provision.GatewayRevocationClient;

/**
 * Wires the {@link DesktopSudoClaimSync} seam + its retry worker, gated behind ONE flag,
 * {@code app.desktop.sudo.claim-sync.enabled} (DEFAULT false). Mirrors
 * {@code BackupStatusReconcilerConfig} / {@code DesktopRemoteInstallConfig} EXACTLY: the
 * mutually-exclusive Noop/real seam pair off one {@code @ConditionalOnProperty}, and the
 * scheduled worker registered ONLY when enabled (the bean is otherwise ABSENT, so no
 * {@code @Scheduled} tick even exists).
 *
 * <h3>SHIPS DARK (a grant/revoke writes ONLY the DB row by default)</h3>
 * With the flag OFF (the DEFAULT — every dev/test/CI run and every deployment until the
 * operator opts in) the seam is the {@link NoopDesktopSudoClaimSync}: nothing dials Casdoor
 * or the gateway, and each row's {@code propagation_state} honestly stays {@code pending}
 * (the claim genuinely has NOT propagated). Flipping the flag true swaps in the
 * {@link CasdoorDesktopSudoClaimSync} AND registers the {@link DesktopSudoClaimReconciler}.
 * The Casdoor write client itself stays independently gated by {@code casdoor.admin.enabled}
 * (a null {@link CasdoorAdminClient} → the sync leg is a logged dry-run and rows stay
 * pending), the same two-gate layering as {@code AddServiceEffector}'s role step.
 *
 * <h3>Single-writer</h3>
 * The worker injects the platform-wide {@link LeaderElection} bean ({@code AlwaysLeader} by
 * default; the k8s {@code Lease} when {@code app.access-suspension.lease.enabled=true}) — the
 * SAME single-writer primitive the suspension/games/backup loops share, so at most one
 * replica sweeps at a time. (The sync's value-idempotent membership write makes it safe even
 * without the Lease.)
 */
@Configuration(proxyBeanMethods = false)
public class DesktopSudoClaimSyncConfig {

    private static final Logger log = LoggerFactory.getLogger(DesktopSudoClaimSyncConfig.class);

    /** Ships-dark default — the pending-reporting Noop, used whenever claim-sync is not enabled. */
    @Bean
    @ConditionalOnProperty(name = "app.desktop.sudo.claim-sync.enabled", havingValue = "false",
            matchIfMissing = true)
    DesktopSudoClaimSync noopDesktopSudoClaimSync() {
        return new NoopDesktopSudoClaimSync();
    }

    /** The REAL Casdoor-writing sync — wired ONLY when claim-sync is enabled. The Casdoor
     *  admin client is OPTIONAL (present only when {@code casdoor.admin.enabled=true});
     *  {@code getIfAvailable()} yields null in a Casdoor-less run so the sync is a logged
     *  dry-run (rows stay pending) rather than a boot failure. */
    @Bean
    @ConditionalOnProperty(name = "app.desktop.sudo.claim-sync.enabled", havingValue = "true")
    DesktopSudoClaimSync casdoorDesktopSudoClaimSync(ObjectProvider<CasdoorAdminClient> casdoor,
                                                     DesktopSudoGrantRepository repo,
                                                     GatewayRevocationClient revocations) {
        return new CasdoorDesktopSudoClaimSync(casdoor.getIfAvailable(), repo, revocations);
    }

    /** The scheduled retry worker — registered ONLY when claim-sync is enabled, so the
     *  {@code @Scheduled} sweep does not even exist by default (the bean is absent). */
    @Bean
    @ConditionalOnProperty(name = "app.desktop.sudo.claim-sync.enabled", havingValue = "true")
    DesktopSudoClaimReconciler desktopSudoClaimReconciler(DesktopSudoGrantRepository repo,
                                                          DesktopSudoClaimSync claimSync,
                                                          LeaderElection leader) {
        log.info("[desktop-sudo-claim] propagation worker ENABLED (single-writer via {})",
                leader.label());
        return new DesktopSudoClaimReconciler(repo, claimSync, leader);
    }
}
