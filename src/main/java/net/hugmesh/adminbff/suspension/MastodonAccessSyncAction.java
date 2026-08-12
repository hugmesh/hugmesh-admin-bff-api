package net.hugmesh.adminbff.suspension;

import io.github.resilience4j.circuitbreaker.annotation.CircuitBreaker;
import org.jspecify.annotations.Nullable;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;
import net.hugmesh.adminbff.homeserver.HomeserverAdminClient;
import net.hugmesh.adminbff.homeserver.HomeserverOutcome;
import net.hugmesh.adminbff.lease.LeaderElection;
import net.hugmesh.adminbff.provision.ServiceTokenBroker;
import net.hugmesh.authcore.casdoor.CasdoorAdminClient;
import net.hugmesh.authcore.provision.GatewayRevocationClient;

import java.time.Instant;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Reconciles ROLE_MASTODON: drives the akkoma account active/suspended state +
 * Casdoor membership from the access_suspension desired state. Circuit breaker
 * {@code akkoma} (a stalled akkoma opens it; the tick skips and retries when it
 * half-opens). Single-writer via the injected {@link LeaderElection}.
 *
 * @see AbstractAccessSyncAction for the shared reconcile shape (GameMasterAdminSyncAction-derived)
 */
@Service
public class MastodonAccessSyncAction extends AbstractAccessSyncAction {

    private final AtomicReference<Instant> lastSuccessAt = new AtomicReference<>(Instant.EPOCH);

    public MastodonAccessSyncAction(@Nullable CasdoorAdminClient casdoor,
                                    HomeserverAdminClient homeserver,
                                    AccessSuspensionRepository repo,
                                    LeaderElection leader,
                                    GatewayRevocationClient gatewayRevocation) {
        super(casdoor, homeserver, repo, leader, gatewayRevocation);
    }

    @Override
    protected String role() {
        return AccessSuspension.ROLE_MASTODON;
    }

    @Override
    protected String platform() {
        return "mastodon";
    }

    @Override
    protected Mono<HomeserverOutcome> suspendHomeserver(String localpart) {
        return homeserver.suspendMastodon(localpart);
    }

    @Override
    protected Mono<HomeserverOutcome> activateHomeserver(String localpart) {
        return homeserver.unsuspendMastodon(localpart);
    }

    /**
     * The akkoma account + its brokered token are keyed on the Mastodon fold
     * ({@code ServiceTokenBroker.mastodonLocalpart}: {@code .-=/}→{@code _}, 30-char cap) at mint
     * time (see {@code ServiceTokenBroker.mastodonToken} + {@code account.mastodon_localpart},
     * Liquibase 291), NOT the stored {@code matrixUser} form. Re-fold the effect localpart so
     * suspend/unsuspend + the coarse gateway key hit the real account (idempotent: folding an
     * already-folded value is a no-op — see {@link AbstractAccessSyncAction#effectLocalpart}).
     */
    @Override
    protected String effectLocalpart(String storedLocalpart) {
        return ServiceTokenBroker.mastodonLocalpart(storedLocalpart);
    }

    public Instant lastSuccessAt() {
        return lastSuccessAt.get();
    }

    @Scheduled(
            fixedDelayString = "${app.access-suspension.reconcile.interval-ms:30000}",
            initialDelayString = "${app.access-suspension.reconcile.initial-delay-ms:15000}")
    public void runTick() {
        runOnce()
                .doOnSuccess(v -> lastSuccessAt.set(Instant.now()))
                .onErrorResume(e -> Mono.empty())
                .subscribe();
    }

    @CircuitBreaker(name = "akkoma")
    public Mono<Void> runOnce() {
        return reconcile();
    }
}
