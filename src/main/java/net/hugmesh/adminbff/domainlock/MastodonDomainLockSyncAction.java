package net.hugmesh.adminbff.domainlock;

import io.github.resilience4j.circuitbreaker.annotation.CircuitBreaker;
import org.jspecify.annotations.Nullable;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;
import net.hugmesh.adminbff.homeserver.HomeserverAdminClient;
import net.hugmesh.adminbff.homeserver.HomeserverOutcome;
import net.hugmesh.adminbff.lease.LeaderElection;
import net.hugmesh.authcore.casdoor.CasdoorAdminClient;

import java.time.Instant;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Reconciles {@code ROLE_MASTODON_DOMAINLOCKED}: drives the akkoma force-local state +
 * the Casdoor marker membership from the domain_lock desired state. Circuit breaker
 * {@code akkoma} (reused — same homeserver as the suspend loop; a stalled akkoma opens
 * it; the tick skips and retries when it half-opens). Single-writer via the injected
 * {@link LeaderElection}.
 *
 * @see AbstractDomainLockSyncAction for the shared ADD-active reconcile shape
 */
@Service
public class MastodonDomainLockSyncAction extends AbstractDomainLockSyncAction {

    private final AtomicReference<Instant> lastSuccessAt = new AtomicReference<>(Instant.EPOCH);

    public MastodonDomainLockSyncAction(@Nullable CasdoorAdminClient casdoor,
                                        HomeserverAdminClient homeserver,
                                        DomainLockRepository repo,
                                        LeaderElection leader) {
        super(casdoor, homeserver, repo, leader);
    }

    @Override
    protected String role() {
        return DomainLock.ROLE_MASTODON_DOMAINLOCKED;
    }

    @Override
    protected Mono<HomeserverOutcome> engageForceLocal(String localpart) {
        return homeserver.forceLocalMastodon(localpart, true);
    }

    @Override
    protected Mono<HomeserverOutcome> releaseForceLocal(String localpart) {
        return homeserver.forceLocalMastodon(localpart, false);
    }

    public Instant lastSuccessAt() {
        return lastSuccessAt.get();
    }

    @Scheduled(
            fixedDelayString = "${app.domain-lock.reconcile.interval-ms:30000}",
            initialDelayString = "${app.domain-lock.reconcile.initial-delay-ms:18000}")
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
