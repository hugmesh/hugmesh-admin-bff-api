package net.hugmesh.adminbff.suspension;

import io.github.resilience4j.circuitbreaker.annotation.CircuitBreaker;
import org.jspecify.annotations.Nullable;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;
import net.hugmesh.adminbff.homeserver.HomeserverAdminClient;
import net.hugmesh.adminbff.homeserver.HomeserverOutcome;
import net.hugmesh.adminbff.lease.LeaderElection;
import net.hugmesh.authcore.casdoor.CasdoorAdminClient;
import net.hugmesh.authcore.provision.GatewayRevocationClient;

import java.time.Instant;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Reconciles ROLE_MATRIX: drives the tuwunel account active/suspended state +
 * Casdoor membership from the access_suspension desired state. Circuit breaker
 * {@code tuwunel} (a stalled tuwunel opens it; the tick skips and retries when it
 * half-opens). Single-writer via the injected {@link LeaderElection}.
 *
 * @see AbstractAccessSyncAction for the shared reconcile shape (GameMasterAdminSyncAction-derived)
 */
@Service
public class MatrixAccessSyncAction extends AbstractAccessSyncAction {

    private final AtomicReference<Instant> lastSuccessAt = new AtomicReference<>(Instant.EPOCH);

    public MatrixAccessSyncAction(@Nullable CasdoorAdminClient casdoor,
                                  HomeserverAdminClient homeserver,
                                  AccessSuspensionRepository repo,
                                  LeaderElection leader,
                                  GatewayRevocationClient gatewayRevocation) {
        super(casdoor, homeserver, repo, leader, gatewayRevocation);
    }

    @Override
    protected String role() {
        return AccessSuspension.ROLE_MATRIX;
    }

    @Override
    protected String platform() {
        return "matrix";
    }

    @Override
    protected Mono<HomeserverOutcome> suspendHomeserver(String localpart) {
        return homeserver.deactivateMatrix(localpart);
    }

    @Override
    protected Mono<HomeserverOutcome> activateHomeserver(String localpart) {
        return homeserver.activateMatrix(localpart);
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

    @CircuitBreaker(name = "tuwunel")
    public Mono<Void> runOnce() {
        return reconcile();
    }
}
