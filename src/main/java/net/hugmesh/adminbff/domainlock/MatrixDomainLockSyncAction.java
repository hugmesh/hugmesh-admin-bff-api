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
 * Reconciles {@code ROLE_MATRIX_DOMAINLOCKED}: drives the tuwunel federation-lock state
 * + the Casdoor marker membership from the domain_lock desired state. Circuit breaker
 * {@code tuwunel} (reused — same homeserver as the suspend loop; a stalled tuwunel
 * opens it; the tick skips and retries when it half-opens). Single-writer via the
 * injected {@link LeaderElection}.
 *
 * <p>NOTE: tuwunel cannot self-enforce per-user federation — the egress NetworkPolicy
 * is the authoritative Matrix backstop. This action drives the homeserver-side
 * federation-lock seam (per-instance isolation + at-lock room hygiene) + keeps the
 * Casdoor marker congruent; the egress leg lands in the generator.
 *
 * @see AbstractDomainLockSyncAction for the shared ADD-active reconcile shape
 */
@Service
public class MatrixDomainLockSyncAction extends AbstractDomainLockSyncAction {

    private final AtomicReference<Instant> lastSuccessAt = new AtomicReference<>(Instant.EPOCH);

    public MatrixDomainLockSyncAction(@Nullable CasdoorAdminClient casdoor,
                                      HomeserverAdminClient homeserver,
                                      DomainLockRepository repo,
                                      LeaderElection leader) {
        super(casdoor, homeserver, repo, leader);
    }

    @Override
    protected String role() {
        return DomainLock.ROLE_MATRIX_DOMAINLOCKED;
    }

    @Override
    protected Mono<HomeserverOutcome> engageForceLocal(String localpart) {
        return homeserver.federationLockMatrix(localpart, true);
    }

    @Override
    protected Mono<HomeserverOutcome> releaseForceLocal(String localpart) {
        return homeserver.federationLockMatrix(localpart, false);
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

    @CircuitBreaker(name = "tuwunel")
    public Mono<Void> runOnce() {
        return reconcile();
    }
}
