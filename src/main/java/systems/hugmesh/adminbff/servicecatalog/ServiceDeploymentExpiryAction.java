package systems.hugmesh.adminbff.servicecatalog;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;
import systems.hugmesh.adminbff.lease.LeaderElection;

import java.time.Instant;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Auto-ENDS service deployments at their {@code ending_at} clock — the App-Store lifecycle
 * single clock. A CLONE of
 * {@link systems.hugmesh.adminbff.suspension.SuspensionExpiryAction}: on each tick it
 * scans {@code ending_at <= now AND state='active'}, and for each row:
 *
 * <ol>
 *   <li>CASes {@code active -> ended} ({@link ServiceDeploymentRepository#markEnded}, which
 *       also stamps {@code ended_at}); only the writer that wins the transition
 *       (rows-updated == 1) proceeds, so a second replica/tick never double-ends — the
 *       SAME single-writer CAS guard as SuspensionExpiryAction;</li>
 *   <li>EMITS the row's {@code enforce_actions} (teardown / revoke-roles / revoke-certs /
 *       alert) via {@link EnforceActionEmitter}, then sets {@code propagation_state} to
 *       {@code applied} (or {@code failed} if the emission errored, which the next tick
 *       self-heals — the 008 propagation_state convention).</li>
 * </ol>
 *
 * <p>Single-writer via the EXISTING {@link LeaderElection} (the SAME lease mechanism the
 * suspension loop uses — not a new one) + the markEnded CAS. Survives restarts: the scan
 * re-selects every overdue row on boot. No-expiry (ending_at NULL) rows are excluded by
 * {@code dueForEnding} and never auto-end.
 *
 * <p><b>SHIPS DARK (PR1).</b> {@link EnforceActionEmitter} only LOGS the actions — it makes
 * NO real ArgoCD teardown, Casdoor role/cert revoke, or alert, and depends on NO such
 * client. The real effectors are wired into that single seam in a LATER increment.
 */
@Service
public class ServiceDeploymentExpiryAction {

    private static final Logger log = LoggerFactory.getLogger(ServiceDeploymentExpiryAction.class);

    private final ServiceDeploymentRepository repo;
    private final LeaderElection leader;
    private final EnforceActionEmitter emitter;

    private final AtomicReference<Instant> lastSuccessAt = new AtomicReference<>(Instant.EPOCH);

    public ServiceDeploymentExpiryAction(ServiceDeploymentRepository repo,
                                         LeaderElection leader,
                                         EnforceActionEmitter emitter) {
        this.repo = repo;
        this.leader = leader;
        this.emitter = emitter;
    }

    public Instant lastSuccessAt() {
        return lastSuccessAt.get();
    }

    @Scheduled(
            fixedDelayString = "${app.service-deployment.expiry.interval-ms:10000}",
            initialDelayString = "${app.service-deployment.expiry.initial-delay-ms:13000}")
    public void runTick() {
        runOnce()
                .doOnSuccess(v -> lastSuccessAt.set(Instant.now()))
                .onErrorResume(e -> Mono.empty())
                .subscribe();
    }

    public Mono<Void> runOnce() {
        if (!leader.isLeader()) {
            log.debug("[deployment-expiry] not leader ({}) — skipping tick", leader.label());
            return Mono.empty();
        }
        return repo.dueForEnding(Instant.now())
                .concatMap(this::endDeployment)
                .then()
                .onErrorResume(e -> {
                    log.warn("[deployment-expiry] tick failed (will retry next tick): {}", e.toString());
                    return Mono.empty();
                });
    }

    /**
     * End one due deployment. CAS-guard first; only the winner of the {@code active->ended}
     * transition emits the enforce actions and records the propagation outcome. A second
     * tick/replica that lost the CAS (rows == 0) does nothing — idempotent.
     */
    Mono<Void> endDeployment(ServiceDeployment d) {
        return repo.markEnded(d.id())
                // CAS guard: only the row that wins the active→ended transition emits enforce actions.
                .flatMap(rows -> emitEnforceIfWon(rows, d));
    }

    /** Skip if the CAS was lost (rows == 0); otherwise emit enforce actions and record the outcome. */
    private Mono<Void> emitEnforceIfWon(Long rows, ServiceDeployment d) {
        if (rows == null || rows == 0) {
            // Another tick/replica already ended this row — nothing to do.
            return Mono.empty();
        }
        log.info("[deployment-expiry] ending {} in {} (id={}) — emitting enforce actions",
                d.serviceKey(), d.domain(), d.id());
        return emitter.emit(d)
                .flatMap(count -> repo.updatePropagationState(d.id(),
                        ServiceDeployment.PROP_APPLIED).thenReturn(count))
                .doOnNext(count -> log.info(
                        "[deployment-expiry] emitted {} enforce action(s) for id={} "
                        + "(SHIPS DARK — no real effect)", count, d.id()))
                .onErrorResume(e -> {
                    // Enforce-leg failed; mark for next tick retry (propagation_state self-heal).
                    log.warn("[deployment-expiry] enforce emit for id={} failed "
                            + "(loop will retry): {}", d.id(), e.toString());
                    return repo.updatePropagationState(d.id(),
                            ServiceDeployment.PROP_FAILED).thenReturn(0);
                })
                .then();
    }
}
